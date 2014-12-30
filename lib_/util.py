#!/usr/bin/env python

import datetime
from dateutil.tz import tzutc
import pytz
import yaml



# shamelessly plundered from repository.edge.tools :-P
#
# recursive getattr()
# syntax is the same as getattr, but the requested
# attribute is a list instead of a string.
#
# e.g. confidence = rgetattr(apiobject,['confidence','value','value'])
#                 = apiobject.confidence.value.value
#
def rgetattr(object_ ,list_ ,default_=None):
    """recursive getattr using a list"""
    if object_ is None:
        return default_
    if len(list_) == 1:
        return getattr(object_, list_[0], default_)
    else:
        return rgetattr(getattr(object_, list_[0], None), list_[1:], default_)

    
def nowutcmin():
    """time now, but only minute-precision"""
    return datetime.datetime.utcnow().replace(second=0,microsecond=0).replace(tzinfo=pytz.utc)


def epoch_start():
    '''it was the best of times, it was the worst of times...'''
    return datetime.datetime.utcfromtimestamp(0).replace(tzinfo=pytz.utc)


def parse_config(file_):
    '''parse a yaml config file'''
    try:
        return(yaml.safe_load(file(file_, 'r')))
    except yaml.YAMLError:
        print('error parsing yaml file: %s; check your syntax!' % file_)
        exit()
