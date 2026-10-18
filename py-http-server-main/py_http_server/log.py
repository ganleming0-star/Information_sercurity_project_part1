import logging

LOG_FORMAT = "%(asctime)s %(levelname)s %(name)s %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


class ColoredFormatter(logging.Formatter):
    GREY = "\x1b[38;20m"
    YELLOW = "\x1b[33;20m"
    RED = "\x1b[31;20m"
    BLUE = "\x1b[34;20m"
    BOLD_RED = "\x1b[31;1m"
    RESET = "\x1b[0m"
    FORMAT = "%(asctime)s %(levelname)s %(name)s %(message)s"
    FORMATTERS = {
        logging.DEBUG: logging.Formatter(BLUE + FORMAT + RESET, DATE_FORMAT),
        logging.INFO: logging.Formatter(GREY + FORMAT + RESET, DATE_FORMAT),
        logging.WARNING: logging.Formatter(YELLOW + FORMAT + RESET, DATE_FORMAT),
        logging.ERROR: logging.Formatter(RED + FORMAT + RESET, DATE_FORMAT),
        logging.CRITICAL: logging.Formatter(BOLD_RED + FORMAT + RESET, DATE_FORMAT),
    }
    DEFAULT_FORMATTER = logging.Formatter()

    def format(self, record):
        return self.FORMATTERS.get(record.levelno, LOG_FORMAT).format(record)


_console_handler = logging.StreamHandler()
_console_handler.setFormatter(ColoredFormatter())
_log_level = logging.DEBUG
_loggers: list[logging.Logger] = []


def getLogger(name: str):
    logger = logging.getLogger(name)
    logger.handlers = [_console_handler]
    logger.setLevel(_log_level)
    _loggers.append(logger)
    return logger


def setLevel(log_level: int | str):
    global _log_level
    _log_level = log_level
    for logger in _loggers:
        logger.setLevel(log_level)


def shutdown():
    logging.shutdown()
