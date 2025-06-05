import click
import logging

from tqdm import tqdm
from requests import get
from os import environ, makedirs, symlink, chmod, remove
from os.path import join, basename, exists
from shutil import rmtree
from tarfile import open as tar_open
from tempfile import mkdtemp, mktemp
from json import loads as json_loads

# from yaml import dump as yaml_dump
from jinja2 import Template
from time import sleep

from mofos.lib.commands.main import __main__
from mofos.lib.kinds import autocomplete, Type
from mofos.lib.domain import (
    Domain,
    get_all_vms,
    get_template_sshpubkey,
    set_template_sshpubkey,
)
from mofos.lib.volume import Volume
from mofos.lib.utils import local_run, error, configure_ssh_known_hosts
from mofos.lib.logger import VmLogger
from mofos.settings import config as cnf, NET_HELPER, Install


log: VmLogger = logging.getLogger(__name__)  # type: ignore

NETBOOT = {
    "debian-stable-amd64": {
        "variant": "debian11",
        "url": "https://deb.debian.org/debian/dists/stable/main/installer-amd64/current/images/netboot/netboot.tar.gz",
    }
}


@__main__.group()
def template():
    """
    Manage templates and upper overlay disks
    """
    pass


class Installer:
    variant: str
    host_ssh_key_pub: str

    def _generate_ssh_host_key(self) -> tuple[str, str]:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519

        priv_key = ed25519.Ed25519PrivateKey.generate()

        priv_openssh = priv_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.OpenSSH,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf8")

        pub_key = priv_key.public_key()
        pub_openssh = pub_key.public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH,
        ).decode("utf8")

        self.host_ssh_key_pub = pub_openssh
        return priv_openssh, pub_openssh


class DebianInstaller(Installer):
    PXELINUX_CFG = """
    # D-I config version 2.0
    default install
    label install
    kernel linux
    append initrd=initrd.gz url=tftp://{gateway}:69/preseed auto=true priority=critical hw-detect/load_firmware=false hw-detect/load_media=false DEBCONF_DEBUG=5 DEBIAN_FRONTEND=newt interface=eth0 domain=localdomain netcfg/get_hostname=linux net.ifnames=0 biosdevname=0 -- quiet
    timeout 0
    """

    def __init__(self, pxe_root: str, gateway: str, variant: str) -> None:
        self.variant = variant
        self.pxe_root = pxe_root
        self.gateway = gateway
        self.preseed_location = join(pxe_root, "preseed")
        self.postinstall_location = join(pxe_root, "postinstall.sh")

    def prepare_pxe(self, install: Install) -> None:
        variables = install.variables.__dict__
        late_command: str = ""

        if install.late_command.script:
            vars = install.late_command.variables.__dict__
            (
                ssh_host_ed25519_key,
                ssh_host_ed25519_key_pub,
            ) = self._generate_ssh_host_key()
            vars["ssh_host_ed25519_key"] = ssh_host_ed25519_key
            vars["ssh_host_ed25519_key_pub"] = ssh_host_ed25519_key_pub

            with open(install.late_command.script, "r") as fp:
                payload = Template(fp.read()).render(vars)
                late_command = (
                    f"tftp -g -l /target/postinstall.sh "
                    f"-r postinstall.sh {self.gateway} "
                    "&& chmod +x /target/postinstall.sh && "
                    "in-target /postinstall.sh && "
                    "in-target rm /postinstall.sh"
                )
                with open(self.postinstall_location, "w") as out:
                    out.write(payload)

        if not install.preseed:
            error("No preseed file defined in the configuration")
        with open(install.preseed, "r") as fp:
            preseed_template = Template(fp.read())
            with open(self.preseed_location, "w") as out:
                variables["late_command"] = late_command
                out.write(preseed_template.render(variables))

        with open(join(self.pxe_root, "pxelinux.cfg", "default"), "w") as fp:
            fp.write(DebianInstaller.PXELINUX_CFG.format(gateway=self.gateway))

        # Giving such permissions opens a window where another unix user on the
        # host system could retrieve sensitive information from the preseed and the post
        # installation script. Such rights are mandatory as the dnsmasq process
        # running as nobody has to read these files
        # TODO: distribute these files over HTTP in a user owned process
        chmod(self.postinstall_location, 0o0644)
        chmod(self.preseed_location, 0o644)
        symlink(
            join(self.pxe_root, "debian-installer", "amd64", "linux"),
            join(self.pxe_root, "linux"),
        )
        symlink(
            join(self.pxe_root, "debian-installer", "amd64", "initrd.gz"),
            join(self.pxe_root, "initrd.gz"),
        )


class PostInstaller:
    pass


@template.command
@click.argument("name", type=str)
@click.option(
    "--distrib",
    type=click.Choice(list(NETBOOT.keys())),
    default="debian-stable-amd64",
)
@click.option(
    "--tags",
    type=click.STRING,
    default="",  # the default from settings will be added later in the code
    help="Tags to determine the post actions to perform",
)
def create(name: str, distrib: str, tags: str = "") -> None:
    """
    Create a template, boot it, run some post install tasks on it, then shutdown, save
    its qcow2 and remove the machine in the libvirt session.
    """
    if name in get_all_vms():
        raise Domain.AlreadyExists(f"{name} already exists")

    # Preparing the PXE ROOT
    pxe_root = mkdtemp(dir="/tmp")

    cachedir = join(environ["HOME"], ".cache", "template-installer")
    filename = join(
        cachedir,
        f"{distrib}-{basename(NETBOOT[distrib]['url'])}",
    )
    makedirs(cachedir, exist_ok=True)
    if not exists(filename):
        response = get(NETBOOT[distrib]["url"], stream=True)
        with open(filename, "wb") as handle:
            for data in tqdm(response.iter_content(chunk_size=1024), unit="kB"):
                handle.write(data)

    archive = tar_open(filename)
    archive.extractall(pxe_root)

    # Create the libvirt network that will host the template installation
    err, out, _ = local_run(
        f"/usr/bin/sudo {NET_HELPER} network create install --pxe_root {pxe_root}",
        want_output=True,
    )
    if err:
        error("Could not create the template network")

    net_info = json_loads(out)

    # Create the PXE ROOT
    installer = DebianInstaller(
        pxe_root, net_info["gateway"], NETBOOT[distrib]["variant"]
    )
    installer.prepare_pxe(cnf.install)

    RAM = 2048
    cpus = 2
    net_model = "virtio"

    if log.isEnabledFor(logging.DEBUG):
        debug = "--autoconsole graphical --wait 1"
    else:
        debug = "--noautoconsole"

    try:
        # Perform the installation
        log.info(f"Installing {name}")
        ret, _, err_output = local_run(
            (
                "/usr/bin/virt-install "
                f"--name={name} --ram={RAM} --vcpus={cpus} "
                f"--disk size={cnf.install.size},pool={cnf.install.pool} "
                f"--network network={net_info['name']},model={net_model} "
                f"--os-variant={installer.variant} "
                "--graphics=spice --hvm --pxe --boot hd "
                "--vsock cid.auto=yes "
                f"{debug}"
            ),
            want_output=True,
        )
        if ret > 1:
            error(
                f"Could not start the template installation [{ret}]: {err_output.decode('utf8')}"
            )

        # Record the SSH host key
        log.info("Configure the SSH host key of the template")
        known_hosts_file = cnf.ssh.known_hosts_file
        configure_ssh_known_hosts(known_hosts_file, installer.host_ssh_key_pub, name)

        template_tags = tags.split(",") if tags != "" else cnf.defaults.tags

        log.info("Waiting for the installation to be complete")
        new_template = Domain(name)
        while not new_template.shutoff():
            sleep(2)
        log.info("Installation is complete")

        # Prepare the hooks
        hooks = {
            tag: cnf.hooks[tag].install
            for tag in template_tags
            if tag in cnf.hooks and cnf.hooks[tag].install is not None
        }
        # Run the hooks
        if hooks:
            log.info(f"Rebooting {name}")
            new_template.start()
            new_template.wait(timeout=600, init_control_master=False)

            for tag, script in hooks.items():
                log.info(f"Running install hook: {tag}")
                cmd = (
                    f"{cnf.hooks[tag].install} {tag} {new_template.name} "
                    f"{new_template.os} {new_template.distrib} {new_template.alias}"
                )
                err, _, _ = local_run(cmd)
                if err:
                    log.warning(f"An error occurred during the hook execution: {tag}")

            new_template.stop()

        log.info("Downloading the resulting qcow2 disk")
        sleep(30)  # Waiting for the disk to correctly sync to disk
        local_run(
            (
                f"/usr/bin/virsh vol-download --pool {cnf.install.pool} "
                f"--vol {name}.qcow2 "
                f"--file {name}.qcow2"
            )
        )
        new_template.remove(new_template.volumes())
        new_template_disk = f"{name}-disk.qcow2"
        log.info("Compressing the disk")
        local_run(
            (
                "/usr/bin/qemu-img convert -c -o compression_type=zstd "
                f"-O qcow2 {name}.qcow2 {new_template_disk}"
            )
        )
        remove(f"{name}.qcow2")
        log.info("Save template's public ssh host key")
        set_template_sshpubkey("disk", new_template_disk, installer.host_ssh_key_pub)
        log.success("Template installation finished")
        log.success(f"Template disk is {name}-disk.qcow2")

    except KeyboardInterrupt:
        pass
    finally:
        rmtree(pxe_root)
        local_run(f"/usr/bin/sudo {NET_HELPER} network destroy {net_info['name']}")


@template.command("import")
@click.argument("name")
@click.argument("file", type=click.Path(exists=True, file_okay=True))
@click.argument("variant", type=click.STRING, shell_complete=autocomplete("variant"))
@click.option("--sshpubkey", type=str, help="SSH public key of template")
@click.option(
    "--network",
    default=cnf.libvirt.network,
    help="Libvirt network in which put the template",
)
@click.option("--netmodel", type=str, default="virtio", help="Network device type")
@click.option("--diskbus", type=str, default="virtio", help="Disk connection bus")
@click.option("--ram", type=int, default=cnf.defaults.ram, help="RAM")
@click.option("--cpus", type=int, default=cnf.defaults.cpus, help="Number of CPUs")
@click.option(
    "--vsock",
    type=bool,
    default=cnf.defaults.vsock,
    help="Enable virtual sockets",
)
@click.option(
    "--shmem",
    type=bool,
    default=cnf.defaults.shmem,
    help="Enable shared memory",
)
@click.option("--tags", type=str, default="", help="Template tags")
def import_template(
    name: str,
    file: str,
    sshpubkey: str,
    network: str = cnf.libvirt.network,
    variant: str = "generic",
    netmodel: str = "virtio",
    diskbus: str = "virtio",
    cpus: int = cnf.defaults.cpus,
    ram: int = cnf.defaults.ram,
    vsock: bool = cnf.defaults.vsock,
    shmem: bool = cnf.defaults.shmem,
    tags: str = "",  # the default from settings will be added later in the code
) -> None:
    """
    Import a qcow2 as a template
    """

    log.info(f"Uploading {file} to {cnf.libvirt.pool} pool")
    new_qcow2 = f"{name}-disk.qcow2"
    ret, _, _ = local_run(
        (
            f"/usr/bin/virsh vol-create-as --pool {cnf.libvirt.pool} "
            f"--capacity {cnf.install.size} "  # TODO, find the size according to the qcow2 file
            f"--format qcow2 {new_qcow2}"
        )
    )
    if ret:
        error(f"Could not allocate the volume {name}")
    ret, _, _ = local_run(
        (
            f"/usr/bin/virsh vol-upload --pool {cnf.libvirt.pool} "
            f"--vol {new_qcow2} --file {file}"
        )
    )
    if ret:
        error(f"Could not upload {file}")

    new_qcow2_path = Volume.from_name(new_qcow2).path
    s_vsock = "--vsock cid.auto=yes" if vsock else ""
    s_shmem = "--memorybacking source.type=memfd,access.mode=shared " if shmem else ""
    s_network = f"network={network}"
    log.info(f"Creating the virtual machine {name}")
    ret, _, _ = local_run(
        (
            "/usr/bin/virt-install "
            f"--name={name} --ram={ram} --vcpus={cpus} "
            f"--disk path={new_qcow2_path},bus={diskbus} "
            "--noautoconsole --graphics=spice --hvm --boot hd "
            f"--network {s_network},model={netmodel} "
            f"--os-variant={variant} {s_vsock} {s_shmem} "
            "--import --noreboot --check path_in_use=off"
        )
    )
    if ret:
        error(f"Could not import {name}")

    known_hosts_file = cnf.ssh.known_hosts_file

    log.info("Configuring the template metadata")
    domain = Domain(name)
    domain.kind = "template"
    domain.tags = tags.split(",") if tags != "" else cnf.defaults.tags
    domain.set_metadata()

    log.info("Configuring the SSH key")
    if sshpubkey is None:
        sshpubkey = get_template_sshpubkey("disk", basename(file))
        if sshpubkey is None:
            log.error(
                "Could not configured the SSH public key, this operation should be done manually"
            )
            raise SystemExit(1)
    configure_ssh_known_hosts(known_hosts_file, sshpubkey, name)
    set_template_sshpubkey("template", name, sshpubkey)

    log.success(f"{name} successfully imported")


@template.command
@click.option(
    "-s",
    "--size",
    default=cnf.install.size,
    help="Size of the upper layer disk (in GB)",
)
def create_overlay_disk(size: int = cnf.install.size) -> None:
    """
    Create the upper layer empty disk.
    """
    overlay_disk = cnf.defaults.overlay.disk

    log.info("Creating the upper layer disk")
    local_run(
        (
            f"/usr/bin/virsh vol-create-as --pool {cnf.libvirt.pool} "
            f"--capacity {size}G "
            f"--format qcow2 {overlay_disk}"
        )
    )
    temp = mktemp()
    log.info("Downloading it to a temp file to format it")
    local_run(
        (
            f"/usr/bin/virsh vol-download --pool {cnf.libvirt.pool} "
            f"--vol {overlay_disk} "
            f"--file {temp}"
        )
    )
    log.info("Formatting the disk")
    local_run(
        (
            "/usr/bin/virt-format --filesystem=ext4 --format=qcow2 "
            f"--label=overlay -a {temp}"
        )
    )
    temp_compressed = mktemp()
    log.info("Compressing the disk")
    local_run(
        (
            "/usr/bin/qemu-img convert -c -o compression_type=zstd "
            f"-O qcow2 {temp} {temp_compressed}"
        )
    )
    log.info(f"Re-uploading it to virsh pool `{cnf.libvirt.pool}`")
    local_run(
        (
            f"/usr/bin/virsh vol-upload --pool {cnf.libvirt.pool} "
            f"--vol {overlay_disk} --file {temp_compressed}"
        )
    )
    remove(temp)
    remove(temp_compressed)


@template.command()
@click.argument("domain", type=Type.domain, shell_complete=autocomplete("stopped"))
@click.argument("template", type=Type.domain, shell_complete=autocomplete("stopped"))
def change(domain: Domain, template: Domain):
    """
    Change the template used by a domain.
    """
    if domain.shutoff() and template.shutoff():
        template_disk = template.storage_files()[0]
        domain.change_template_disk(template_disk)
        log.info(f"Attaching new template disk: {template_disk}")
        template_host_key = get_template_sshpubkey("template", template.name)
        if template_host_key is not None:
            configure_ssh_known_hosts(
                cnf.ssh.known_hosts_file, template_host_key, domain.name
            )
        log.info("Updating ssh host key entries")
    else:
        error(f"{domain} is started")
