"""Application CLI locale context, separate from transport and action mechanics."""
import os
from pathlib import Path

from bmcyber.interface.Localizer import Localizer


def command_text():
    preference = os.environ.get('LC_ALL') or os.environ.get('LANG', 'en')
    return Localizer(Path(__file__).parents[1] / 'locales'), preference.split('.')[0]
