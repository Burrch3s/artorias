"""
Contains functions to format and color information back to user.
Basically, functions that I want because white on black wall o' text
is not always ideal
"""

import logging
from colors import color
from datetime import datetime

def add_color_first(
        msg_color='',
        msg_no_color='',
        new_color='',
        new_style='',
        new_end='\n',
        new_sep=' '):
    """
    Function to print 2 items, the first is with color, the second without color
    """
    print(color(msg_color, fg=new_color, style=new_style),
          msg_no_color, end=new_end, sep=new_sep)

def add_color_later(
        msg_color='',
        msg_no_color='',
        new_color='',
        new_style='',
        new_end='\n',
        new_sep=' '):
    """
    Function to print 2 items, the first is without color, the second with color
    """
    print(msg_no_color, color(msg_color, fg=new_color, style=new_style),
          end=new_end, sep=new_sep)

def low(text: str) -> None:
    """
    Print out a low priority message to the user
    """
    time = datetime.now().strftime("%m/%d %H:%M.%S")
    msg = "[***] {}:".format(time)
    add_color_first(msg_color=msg, msg_no_color=text, new_style='bold')
    logging.info("[{}]: {}".format(time, text))

def warning(text: str) -> None:
    """
    Print out a warning message to the user
    """
    time = datetime.now().strftime("%m/%d %H:%M.%S")
    msg = "[***] {}:".format(time)
    add_color_first(msg_color=msg, msg_no_color=text,
                    new_color='yellow', new_style='bold')
    logging.warning("[{}]: {}".format(time, text))

def error(text: str) -> None:
    """
    Print out a error message to the user
    """
    time = datetime.now().strftime("%m/%d %H:%M.%S")
    msg = "[***] {}:".format(time)
    add_color_first(msg_color=msg, msg_no_color=text,
                    new_color=196, new_style='bold')
    logging.error("[{}]: {}".format(time, text))

def success(text: str) -> None:
    """
    Print out a debug message to the user
    """
    time = datetime.now().strftime("%m/%d %H:%M.%S")
    msg = "[***] {}:".format(time)
    add_color_first(msg_color=msg, msg_no_color=text,
                    new_color='green', new_style='bold')
    logging.info("[{}]: {}".format(time, text))

def debug(text: str) -> None:
    """
    Print out a debug message to the user
    """
    time = datetime.now().strftime("%m/%d %H:%M.%S")
    msg = "[***] {}:".format(time)
    add_color_first(msg_color=msg, msg_no_color=text,
                    new_color=51, new_style='bold')
    logging.debug("[{}]: {}".format(time, text))

