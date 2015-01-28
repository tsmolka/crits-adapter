#!/usr/bin/env python2.7

from bson import json_util
from copy import deepcopy
from dateutil.tz import tzutc
import atexit
import crits_
import datetime
import edge_
import hashlib
import os
import os.path
import pytz
import signal
import sys
import time
import yaml


# shamelessly plundered from repository.edge.tools
#
# recursive getattr()
# syntax is the same as getattr, but the requested
# attribute is a list instead of a string.
#
# e.g. confidence = rgetattr(apiobject,['confidence','value','value'])
#                 = apiobject.confidence.value.value
#
def rgetattr(object_, list_, default_=None):
    """recursive getattr using a list"""
    if object_ is None:
        return default_
    if len(list_) == 1:
        return getattr(object_, list_[0], default_)
    else:
        return rgetattr(getattr(object_, list_[0], None), list_[1:], default_)


# shamelessly plundered from repository.edge.tools
def dicthash_sha1(d, salt=''):
    """return a unique fingerprint/hash for a nested dict
    lots of different methods here:
    http://stackoverflow.com/questions/5884066/hashing-a-python-dictionary
    """
    assert isinstance(d, dict)
    return hashlib.sha1(salt + json_util.dumps(d, sort_keys=True)).hexdigest()


def nowutc():
    """utc now"""
    return datetime.datetime.utcnow().replace(tzinfo=pytz.utc)


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


def signal_handler(num, frame):
    '''signal handler function for Daemon'''
    sys.exit()


class Daemon:
    '''generic daemon class'''
    def __init__(self, config, stdin='/dev/null',
                 stdout='/dev/null', stderr='/dev/null'):
        self.stdin = stdin
        self.stdout = stdout
        self.stderr = stderr
        self.config = config
        self.working_dir = self.config['daemon']['working_dir']
        self.pidfile = os.path.join(self.working_dir, config['daemon']['pid'])
        self.logger = self.config['logger']
        self.db = self.config['db']

    def daemonize(self):
        '''do the UNIX double-fork magic, see Stevens' "Advanced
        Programming in the UNIX Environment" for details (ISBN
        0201563177)
        http://www.erlenstar.demon.co.uk/unix/faq_2.html#SEC16'''
        try:
            pid = os.fork()
            if pid > 0:
                # exit first parent
                sys.exit(0)
        except OSError as e:
            self.logger.error("fork #1 failed: %d (%s)\n"
                              % (e.errno, e.strerror))
            self.logger.exception(e)
            sys.exit(1)
        # decouple from parent environment
        os.chdir(self.working_dir)
        os.setsid()
        os.umask(0)
        # do second fork
        try:
            pid = os.fork()
            if pid > 0:
                # exit from second parent
                sys.exit(0)
        except OSError as e:
            self.logger.error("fork #2 failed: %d (%s)\n"
                              % (e.errno, e.strerror))
            self.logger.exception(e)
            sys.exit(1)
        # redirect standard file descriptors
        if not self.config['daemon']['debug']:
            sys.stdout.flush()
            sys.stderr.flush()
            si = file(self.stdin, 'r')
            so = file(self.stdout, 'a+')
            se = file(self.stderr, 'a+', 0)
            os.dup2(si.fileno(), sys.stdin.fileno())
            os.dup2(so.fileno(), sys.stdout.fileno())
            os.dup2(se.fileno(), sys.stderr.fileno())
        atexit.register(self.cleanup_and_die)
        # write pidfile
        pid = str(os.getpid())
        try:
            file(self.pidfile, 'w+').write("%s\n" % pid)
        except Exception as e:
            self.logger.error('could not write to pidfile %s' % self.pidfile)
            self.logger.exception(e)

    def cleanup_and_die(self):
        '''cleanup function'''
        self.logger.info('SIGINT received! '
                         'Cleaning up and killing processes...')
        try:
            os.remove(self.pidfile)
        except Exception as e:
            self.logger.error('could not delete pidfile %s' % self.pidfile)
            self.logger.exception(e)

    def start(self):
        '''Start the daemon'''
        # Check for a pidfile to see if the daemon already runs
        pid = None
        try:
            if os.path.isfile(self.pidfile):
                pf = file(self.pidfile, 'r')
                pid = int(pf.read().strip())
                pf.close()
        except IOError as e:
            self.logger.error('could not access pidfile %s' % self.pidfile)
            self.logger.exception(e)
        if pid:
            self.logger.error(
                'pidfile %s already exists. Daemon already running?' %
                self.pidfile)
            sys.exit(1)
        # Start the daemon
        self.daemonize()
        self.run()

    def stop(self):
        '''Stop the daemon'''
        # Get the pid from the pidfile
        try:
            pf = file(self.pidfile, 'r')
            pid = int(pf.read().strip())
            pf.close()
        except IOError as e:
            pid = None
            self.logger.error('could not access pidfile %s' % self.pidfile)
            self.logger.exception(e)
        if not pid:
            self.logger.error(
                'pidfile %s does not exist. Daemon not running?' %
                self.pidfile)
            return  # not an error in a restart
        # Try killing the daemon process
        try:
            while True:
                os.kill(pid, signal.SIGTERM)
                time.sleep(0.1)
        except OSError as e:
            # process is already dead
            if str(e).find("No such process") > 0:
                if os.path.exists(self.pidfile):
                    os.remove(self.pidfile)
            else:
                self.logger.error('something went wrong while trying '
                                  'to kill process %i' % pid)
                self.logger.exception(e)
                sys.exit(1)

    def restart(self):
        '''Restart the daemon'''
        self.stop()
        self.start()

    def get_poll_interval(self, c_site):
        poll_interval = \
            self.config['crits']['sites'][c_site]['api']['poll_interval']
        return(poll_interval)

    def run(self):
        '''daemon main logic'''
        while True:
            enabled_crits_sites = list()
            enabled_edge_sites = list()
            for c_site in self.config['crits']['sites'].keys():
                if self.config['crits']['sites'][c_site]['enabled']:
                    enabled_crits_sites.append(c_site)
            for e_site in self.config['edge']['sites'].keys():
                if self.config['edge']['sites'][e_site]['enabled']:
                    enabled_edge_sites.append(e_site)
            # sync crits to edge
            for c_site in enabled_crits_sites:
                for e_site in enabled_edge_sites:
                    # check if (and when) we synced source and destination...
                    now = nowutc()
                    last_run = self.db.get_last_sync(source=c_site,
                                                     destination=e_site,
                                                     direction='c2e')
                    last_run = last_run.replace(tzinfo=pytz.utc)
                    poll_interval = self.get_poll_interval(c_site)
                    if now >= \
                       last_run + datetime.timedelta(seconds=poll_interval):
                        self.logger.info('initiating crits=>edge sync between '
                                         '%s and %s' % (c_site, e_site))
                        completed_run = crits_.crits2edge(self.config, c_site,
                                                          e_site, daemon=True,
                                                          now=now,
                                                          last_run=last_run)
                        if completed_run:
                            self.db.set_last_sync(source=c_site,
                                                  destination=e_site,
                                                  direction='c2e',
                                                  timestamp=completed_run)
            # sync edge to crits
            for e_site in enabled_edge_sites:
                for c_site in enabled_crits_sites:
                    now = nowutc()
                    last_run = self.db.get_last_sync(source=e_site,
                                                     destination=c_site,
                                                     direction='e2c')
                    last_run = last_run.replace(tzinfo=pytz.utc)
                    poll_interval = self.get_poll_interval(e_site)
                    if now >= \
                       last_run + datetime.timedelta(seconds=poll_interval):
                        self.logger.info('initiating edge=>crits sync between '
                                         '%s and %s' % (e_site, c_site))
                        completed_run = edge_.edge2crits(self.config, e_site,
                                                         c_site, daemon=True,
                                                         now=now,
                                                         last_run=last_run)
                        if completed_run:
                            self.db.set_last_sync(source=e_site,
                                                  destination=c_site,
                                                  direction='e2c',
                                                  timestamp=completed_run)
            time.sleep(1)
