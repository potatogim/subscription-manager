# -*- coding: utf-8 -*-
#
# Copyright (c) 2020 Red Hat, Inc.
#
# This software is licensed to you under the GNU General Public License,
# version 2 (GPLv2). There is NO WARRANTY for this software, express or
# implied, including the implied warranties of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. You should have received a copy of GPLv2
# along with this software; if not, see
# http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.
#
# Red Hat trademarks are not licensed under GPLv2. No permission is
# granted to use or replicate Red Hat trademarks that are incorporated
# in this software or its documentation.
#

"""
This module implements base class for collecting metadata from cloud provider
"""

import requests
import logging


log = logging.getLogger(__name__)


class CloudCollector(object):
    """
    Base class for collecting metadata and signature of metadata from cloud
    provider. The most of logic is implemented in this class. Subclasses
    for concrete cloud providers usually contains only default values in
    class attributes. All values will be usually loaded from configuration
    files of cloud providers. It is/will be still possible to implement
    custom method for e.g. getting metadata from cloud provider.
    """

    # Unique ID of cloud provider
    # (e.g. "aws", "azure", "gcp", etc.)
    CLOUD_PROVIDER_ID = None

    # Path to configuration file of collector (ini file)
    # (e.g. /etc/rhsm/cloud_providers/cool_cloud.conf
    COLLECTOR_CONF_FILE = None

    # Default value of server URL providing metadata
    # (e.g. http://1.2.3.4./path/to/metadata/document)
    CLOUD_PROVIDER_METADATA_URL = None

    # Type of metadata document returned by server
    # (e.g. "application/json", "text/xml")
    CLOUD_PROVIDER_METADATA_TYPE = None

    # Default value of server URL providing signature of metadata
    # (e.g. http://1.2.3.4/path/to/signature/document)
    CLOUD_PROVIDER_SIGNATURE_URL = None

    # Type of signature document returned by server
    # (e.g. "application/json", "text/xml", "text/pem")
    CLOUD_PROVIDER_SIGNATURE_TYPE = None

    # Default value of path to cache file holding metadata
    # (e.g. /var/lib/rhsm/cache/cool_cloud_metadata.json)
    METADATA_CACHE_FILE = None

    # Default value of path to holding signature of metadata
    # (e.g. /var/lib/rhsm/cache/cool_cloud_signature.json)
    SIGNATURE_CACHE_FILE = None

    # Custom HTTP headers like user-agent
    HTTP_HEADERS = {}

    def __init__(self):
        """
        Initialize instance of CloudCollector
        """
        self.metadata = None
        self.signature = None

    def _get_metadata_from_cache(self):
        """
        Method for gathering metadata from cache file
        :return: string containing metadata
        """
        raise NotImplementedError

    def _get_data_from_server(self, data_type, url):
        """
        Try to get some data from server using method GET
        :data_type: string representing data type (metadata, signature, token)
        :param url: URL of the GET request
        :return: String representing body, when status code is 200; Otherwise return None
        """
        log.debug(f'Trying to get {data_type} from {url}')

        try:
            response = requests.get(url, headers=self.HTTP_HEADERS)
        except requests.ConnectionError as err:
            log.debug(f'Unable to get {self.CLOUD_PROVIDER_ID} {data_type}: {err}')
        else:
            if response.status_code == 200:
                return response.text
            else:
                log.debug(f'Unable to get {self.CLOUD_PROVIDER_ID} {data_type}: {response.status_code}')

    def _get_metadata_from_server(self):
        """
        Method for gathering metadata from server
        :return: String containing metadata or None
        """
        return self._get_data_from_server("metadata", self.CLOUD_PROVIDER_METADATA_URL)

    def _get_signature_from_cache_file(self):
        """
        Try to get signature from cache file
        :return: string containing signature
        """
        raise NotImplementedError

    def _get_signature_from_server(self):
        """
        Method for gathering signature of metadata from server
        :return: String containing signature or None
        """
        return self._get_data_from_server("signature", self.CLOUD_PROVIDER_SIGNATURE_URL)

    def get_signature(self):
        """
        Public method for getting signature (cache file or server)
        :return:
        """
        signature = self._get_signature_from_cache_file()

        if signature is None:
            signature = self._get_signature_from_server()

        return signature

    def get_metadata(self):
        """
        Public method for getting metadata (cache file or server)
        :return:
        """
        metadata = self._get_metadata_from_cache()

        if metadata is not None:
            return metadata

        return self._get_metadata_from_server()
