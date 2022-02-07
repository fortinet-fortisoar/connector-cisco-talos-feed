""" Copyright start
  Copyright (C) 2008 - 2022 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

import requests
from connectors.core.connector import get_logger, ConnectorError

error_msg = {
    401: 'Authentication failed due to invalid credentials',
    429: 'Rate limit was exceeded',
    403: 'Token is invalid or expired',
    "ssl_error": 'SSL certificate validation failed',
    'time_out': 'The request timed out while trying to connect to the remote server',
}
logger = get_logger('cisco-talos-feed')

try:
    from integrations.crudhub import trigger_ingest_playbook
except:
    # ignore. lower FSR version
    pass


class CISCOTalosFeed(object):
    def __init__(self, config):
        self.server_url = config.get('server_url', '').strip('/')
        if not self.server_url.startswith('http') or not self.server_url.startswith('https'):
            self.server_url = 'https://' + self.server_url
        self.verify_ssl = config.get('verify_ssl', None)


    def make_rest_call(self, endpoint, params=None, data=None, method='GET'):
        service_endpoint = '{0}{1}'.format(self.server_url, endpoint)
        logger.debug('API Request Endpoint: {0}'.format(service_endpoint))
        logger.debug('API Request Parameters: {0}'.format(params))
        try:
            response = requests.request(method, service_endpoint, headers=None, data=data, params=params,
                                        verify=self.verify_ssl)
            logger.debug('API Status Code: {0}'.format(response.status_code))
            logger.debug('API Response: {0}'.format(response.text))
            if response.ok:
                return response.text
            else:
                logger.error("Error: {0}".format(response.text))
                raise ConnectorError('{0}'.format(error_msg.get(response.status_code, response.text)))
            response.raise_for_status()
        except requests.exceptions.SSLError as e:
            logger.exception('{0}'.format(e))
            raise ConnectorError('{0}'.format(error_msg.get('ssl_error')))
        except requests.exceptions.ConnectionError as e:
            logger.exception('{0}'.format(e))
            raise ConnectorError('{0}'.format(error_msg.get('time_out')))
        except Exception as e:
            logger.error('{0}'.format(e))
            raise ConnectorError('{0}'.format(e))


def fetch_indicators(config, params, **kwargs):
    try:
        talos = CISCOTalosFeed(config)
        mode = params.get('output_mode')
        create_pb_id = params.get("create_pb_id")
        resp = talos.make_rest_call('/documents/ip-blacklist')
        list_indicators =  list(set(resp.split('\n') if resp else []))
        indicators = [indicator for indicator in list_indicators if indicator]
        if mode == 'Create as Feed Records in FortiSOAR':
            trigger_ingest_playbook(indicators, create_pb_id, parent_env=kwargs.get('env', {}),
                                    batch_size=1000)
            return 'Successfully triggered playbooks to create feed records'
        else:
            return indicators
    except Exception as err:
        logger.error(err)
        raise ConnectorError(err)


def _check_health(config):
    try:
        talos = CISCOTalosFeed(config)
        resp = talos.make_rest_call('/documents/ip-blacklist')
    except Exception as err:
        logger.error(err)
        raise ConnectorError(err)


operations = {
    'fetch_indicators': fetch_indicators
}
