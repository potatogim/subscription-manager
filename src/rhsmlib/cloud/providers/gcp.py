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
This is module implementing detector and metadata collector of virtual machine running on Google Cloud Platform
"""
import logging

from typing import Union

from rhsmlib.cloud.detector import CloudDetector
from rhsmlib.cloud.collector import CloudCollector


class GCPCloudDetector(CloudDetector):
    """
    Detector of cloud provider
    """

    ID = 'gcp'

    def __init__(self, hw_info):
        """
        Initialize instance of GCPCloudDetector
        """
        super(GCPCloudDetector, self).__init__(hw_info)

    def is_vm(self):
        """
        Is system running on virtual machine or not
        :return: True, when machine is running on VM; otherwise return False
        """
        return super(GCPCloudDetector, self).is_vm()

    def is_running_on_cloud(self):
        """
        Try to guess if cloud provider is GCP using collected hardware information (output of dmidecode,
        virt-what, etc.)
        :return: True, when we detected sign of GCP in hardware information; Otherwise return False
        """

        # The system has to be VM
        if self.is_vm() is False:
            return False
        # This is valid for virtual machines running on Google Cloud Platform
        if 'dmi.bios.vendor' in self.hw_info and \
                'google' in self.hw_info['dmi.bios.vendor'].lower():
            return True
        # In other cases return False
        return False

    def is_likely_running_on_cloud(self):
        """
        Return non-zero value, when the machine is virtual machine and it is running on kvm and
        some google string can be found in output of dmidecode
        :return: Float value representing probability that vm is running on GPC
        """
        probability = 0.0

        # When the machine is not virtual machine, then there is probably zero chance that the machine
        # is running on GPC
        if self.is_vm() is False:
            return 0.0

        # We know that GCP uses only KVM at the end of 2020
        if 'virt.host_type' in self.hw_info and 'kvm' in self.hw_info['virt.host_type']:
            probability += 0.3

        # Try to find "Google" or "gcp" keywords in output of dmidecode
        found_google = False
        found_gcp = False
        for hw_item in self.hw_info.values():
            if type(hw_item) != str:
                continue
            if 'google' in hw_item.lower():
                found_google = True
            elif 'gcp' in hw_item.lower():
                found_gcp = True
        if found_google is True:
            probability += 0.3
        if found_gcp is True:
            probability += 0.1

        return probability


class GCPCloudCollector(CloudCollector):
    """
    Collector of Google Cloud Platform metadata. Verification of instance identity is described in this document:

    https://cloud.google.com/compute/docs/instances/verifying-instance-identity
    """

    CLOUD_PROVIDER_ID = "gcp"

    # The "audience" should be some unique URI agreed upon by both the instance and the system verifying
    # the instance's identity. For example, the audience could be a URL for the connection between the two systems.
    # But it can be anything.
    AUDIENCE = "RHSM/1.0"

    # Google uses
    CLOUD_PROVIDER_METADATA_URL = f"http://metadata/computeMetadata/v1/instance/service-accounts/default/identity?audience={AUDIENCE}&format=full"

    CLOUD_PROVIDER_METADATA_TYPE = "text/html"

    # Token
    CLOUD_PROVIDER_METADATA_TTL = 3600

    CLOUD_PROVIDER_SIGNATURE_URL = None

    CLOUD_PROVIDER_SIGNATURE_TYPE = None

    HTTP_HEADERS = {
        'user-agent': 'RHSM/1.0',
        'Metadata-Flavor': 'Google'
    }

    # It is not save cache file
    METADATA_CACHE_FILE = None

    # Nothing to cache for this cloud provider
    SIGNATURE_CACHE_FILE = None

    def __init__(self):
        super(GCPCloudCollector, self).__init__()

    def _get_metadata_from_cache(self) -> None:
        """
        It is not safe to cache metadata returned from server
        :return: None
        """
        return None

    def _get_data_from_server(self, data_type, url) -> Union[str, None]:
        """
        Try to get data from metadata server
        """
        return super(GCPCloudCollector, self)._get_data_from_server(data_type, url)

    def _get_metadata_from_server(self) -> Union[str, None]:
        """
        GCP metadata server returns only one file called token
        :return: String with token or None
        """
        return self._get_data_from_server(data_type="token", url=self.CLOUD_PROVIDER_METADATA_URL)

    def _get_signature_from_server(self):
        """
        Google returns everything in one file.
        """
        return None

    def _get_signature_from_cache_file(self):
        """
        Really no need to cache signature
        """
        return None

    def get_signature(self):
        """
        Google returns everything in one file. No need to try to get signature
        """
        return None

    def get_metadata(self):
        return super(GCPCloudCollector, self).get_metadata()

# Note about GCP token
# --------------------
#
# It is possible to verify token, but is not easy to do it on RHEL, because it requires
# special Python packages that are not available on RHEL. It is recommended to create
# virtual environment:
#
# $ python3 -m venv env
#
# Activate virtual environment:
#
# $ source env/bin/activate
#
# Install required packages:
#
# $ pip install --upgrade google-auth
# $ pip install requests
#
# Run following Python script:
#
# ```python
# from rhsmlib.cloud.providers.gcp import GCPCloudCollector
# # Import libraries for token verification
# import google.auth.transport.requests
# from google.oauth2 import id_token
# # Get token
# token = GCPCloudCollector().get_metadata()
# # Verify token signature and store the token payload
# request = google.auth.transport.requests.Request()
# payload = id_token.verify_token(token, request=request, audience=GCPCloudCollector.AUDIENCE)
# print(payload)
# ```


def _smoke_test():
    """
    Simple smoke tests of GCP detector and collector
    """
    # Gather only information about hardware and virtualization
    from rhsmlib.facts.host_collector import HostCollector
    from rhsmlib.facts.hwprobe import HardwareCollector

    import sys

    root = logging.getLogger()
    root.setLevel(logging.DEBUG)

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    root.addHandler(handler)

    facts = {}
    facts.update(HostCollector().get_all())
    facts.update(HardwareCollector().get_all())
    gcp_cloud_detector = GCPCloudDetector(facts)
    result = gcp_cloud_detector.is_running_on_cloud()
    probability = gcp_cloud_detector.is_likely_running_on_cloud()
    print('>>> debug <<< result: %s, %6.3f' % (result, probability))
    if result is True:
        gcp_cloud_collector = GCPCloudCollector()
        token = gcp_cloud_collector.get_metadata()
        print(f'>>> debug <<< token: {token}')


# Some temporary smoke testing code. You can test this module using:
# sudo PYTHONPATH=./src:./syspurse/src python3 -m rhsmlib.cloud.providers.gcp
if __name__ == '__main__':
    _smoke_test()