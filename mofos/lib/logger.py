from colorama import Style, Fore
from logging import Formatter, LogRecord
from logging.config import dictConfig
from typing import Any
import logging

SUCCESS_LEVEL_NUM = 25
logging.addLevelName(SUCCESS_LEVEL_NUM, "SUCCESS")


class VmLogger(logging.Logger):
    def __init__(self, name: str):
        super().__init__(name)

    def success(self, message, *args, **kwargs):
        if self.isEnabledFor(SUCCESS_LEVEL_NUM):
            self._log(SUCCESS_LEVEL_NUM, message, args, **kwargs)


class ErrorFilter(logging.Filter):
    def filter(self, record: LogRecord) -> bool:
        return record.levelno == logging.DEBUG or record.levelno >= logging.ERROR


class NonErrorFilter(logging.Filter):
    def filter(self, record: LogRecord) -> bool:
        return record.levelno < logging.ERROR


class LogFormatter(Formatter):
    def format(self, record: LogRecord) -> str:
        prefix = ""
        if record.levelno == 10:
            prefix = f"{record.levelname}:{record.pathname}:{record.lineno} "
        elif record.levelno == 20:
            prefix = f"{Fore.WHITE}{Style.BRIGHT}[{Fore.BLUE}*{Fore.WHITE}] "
        elif record.levelno == 25:
            prefix = f"{Fore.WHITE}{Style.BRIGHT}[{Fore.GREEN}+{Fore.WHITE}] "
        elif record.levelno == 30:
            prefix = f"{Fore.WHITE}{Style.BRIGHT}[{Fore.YELLOW}!{Fore.WHITE}] "
        elif record.levelno == 40:
            prefix = f"{Fore.WHITE}{Style.BRIGHT}[{Fore.RED}-{Fore.WHITE}] "

        return f"{prefix}{record.getMessage()}{Style.RESET_ALL}"


LOG_CONFIG: dict[str, Any] = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "custom": {
            "()": LogFormatter,
            "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        },
    },
    "filters": {
        "error_filter": {
            "()": ErrorFilter,
        },
        "non_error_filter": {
            "()": NonErrorFilter,
        },
    },
    "handlers": {
        "stdout": {
            "level": "INFO",
            "class": "logging.StreamHandler",
            "formatter": "custom",
            "stream": "ext://sys.stdout",
            "filters": ["non_error_filter"],
        },
        "stderr": {
            "level": "ERROR",
            "class": "logging.StreamHandler",
            "formatter": "custom",
            "stream": "ext://sys.stderr",
            "filters": ["error_filter"],
        },
    },
    "loggers": {
        "": {
            "handlers": ["stdout", "stderr"],
            "level": "INFO",
            "propagate": True,
        },
    },
}


def configure_logging(debug: bool = False):
    cfg = LOG_CONFIG
    cfg["handlers"]["stderr"]["level"] = "DEBUG" if debug else "ERROR"
    cfg["loggers"][""]["level"] = "DEBUG" if debug else "INFO"
    dictConfig(cfg)
