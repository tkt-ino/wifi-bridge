from logging import getLogger, Formatter, StreamHandler, DEBUG, INFO

def get_module_logger(module, verbose=False):
    logger = getLogger(module)
    logger = _set_handler(logger, StreamHandler(), verbose)
    logger.setLevel(DEBUG)
    logger.propagate = False
    return logger


def _set_handler(logger, handler, verbose):
    if verbose:
        handler.setLevel(DEBUG)
    else:
        handler.setLevel(INFO)
    handler.setFormatter(Formatter('%(asctime)s %(name)s:%(lineno)s %(funcName)s [%(levelname)s]: %(message)s'))
    logger.addHandler(handler)
    return logger
