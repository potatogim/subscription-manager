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
Module for testing Python all modules from Python package rhsmlib.cloud
"""

try:
    import unittest2 as unittest
except ImportError:
    import unittest

from mock import patch, Mock

from rhsmlib.cloud.providers import aws, azure, gcp
from rhsmlib.cloud.utils import detect_cloud_provider


class TestAWSDetector(unittest.TestCase):
    """
    Class used for testing detector of AWS
    """

    def test_aws_not_vm(self):
        """
        Test for the case, when the machine is host (not virtual machine)
        """
        # We will mock facts using simple dictionary
        facts = {
            'virt.is_guest': False,
            'dmi.bios.version': 'cool hardware company'
        }
        aws_detector = aws.AWSCloudDetector(facts)
        is_vm = aws_detector.is_vm()
        self.assertFalse(is_vm)

    def test_aws_vm_using_xen(self):
        """
        Test for the case, when the vm is running on AWS Xen
        """
        # We will mock facts using simple dictionary
        facts = {
            'virt.is_guest': True,
            'virt.host_type': 'xen',
            'dmi.bios.version': 'amazon'
        }
        aws_detector = aws.AWSCloudDetector(facts)
        is_vm = aws_detector.is_vm()
        self.assertTrue(is_vm)
        is_aws_xen_vm = aws_detector.is_running_on_cloud()
        self.assertTrue(is_aws_xen_vm)

    def test_aws_vm_using_kvm(self):
        """
        Test for the case, when the vm is running on AWS KVM
        """
        # We will mock facts using simple dictionary
        facts = {
            'virt.is_guest': True,
            'virt.host_type': 'kvm',
            'dmi.bios.version': '1.0',
            'dmi.bios.vendor': 'Amazon EC2'
        }
        aws_detector = aws.AWSCloudDetector(facts)
        is_vm = aws_detector.is_vm()
        self.assertTrue(is_vm)
        is_aws_kvm_vm = aws_detector.is_running_on_cloud()
        self.assertTrue(is_aws_kvm_vm)

    def test_vm_not_on_aws_cloud(self):
        """
        Test for the case, when the vm is not running on AWS
        """
        # We will mock facts using simple dictionary
        facts = {
            'virt.is_guest': True,
            'virt.host_type': 'kvm',
            'dmi.bios.version': '1.0',
            'dmi.bios.vendor': 'Foo'
        }
        aws_detector = aws.AWSCloudDetector(facts)
        is_vm = aws_detector.is_vm()
        self.assertTrue(is_vm)
        is_aws_vm = aws_detector.is_running_on_cloud()
        self.assertFalse(is_aws_vm)

    def test_vm_without_dmi_bios_info(self):
        """
        Test for the case, when SM BIOS does not provide any useful information for our code
        """
        # We will mock facts using simple dictionary
        facts = {}
        aws_detector = aws.AWSCloudDetector(facts)
        is_vm = aws_detector.is_vm()
        self.assertFalse(is_vm)
        is_aws_vm = aws_detector.is_running_on_cloud()
        self.assertFalse(is_aws_vm)

    def test_vm_system_uuid_starts_with_ec2(self):
        """
        Test for the case, when system UUID starts with EC2 string as it is described here:
        https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/identify_ec2_instances.html
        """
        # We will mock facts using simple dictionary
        facts = {
            'virt.is_guest': True,
            'dmi.system.uuid': 'EC2263F8-15F3-4A34-B186-FAD8AB963431'
        }
        aws_detector = aws.AWSCloudDetector(facts)
        is_vm = aws_detector.is_vm()
        self.assertTrue(is_vm)
        probability = aws_detector.is_likely_running_on_cloud()
        self.assertEqual(probability, 0.1)


class TestAzureDetector(unittest.TestCase):
    """
    Class used for testing detector of Azure
    """

    def test_azure_not_vm(self):
        """
        Test for the case, when the machine is host (not virtual machine)
        """
        # We will mock facts using simple dictionary
        facts = {
            'virt.is_guest': False,
            'dmi.bios.version': 'cool hardware company'
        }
        azure_detector = azure.AzureCloudDetector(facts)
        is_vm = azure_detector.is_vm()
        self.assertFalse(is_vm)

    def test_azure_vm(self):
        """
        Test for the case, when the vm is running on Azure
        """
        # We will mock facts using simple dictionary
        facts = {
            'virt.is_guest': True,
            'virt.host_type': 'hyperv',
            'dmi.bios.version': '090008',
            'dmi.chassis.asset_tag': '7783-7084-3265-9085-8269-3286-77'
        }
        azure_detector = azure.AzureCloudDetector(facts)
        is_vm = azure_detector.is_vm()
        self.assertTrue(is_vm)
        is_azure_vm = azure_detector.is_running_on_cloud()
        self.assertTrue(is_azure_vm)

    def test_vm_not_on_azure_cloud(self):
        """
        Test for the case, when the vm is not running on AWS
        """
        # We will mock facts using simple dictionary
        facts = {
            'virt.is_guest': True,
            'virt.host_type': 'hyperv',
            'dmi.bios.version': '090008',
            'dmi.bios.vendor': 'Foo'
        }
        azure_detector = azure.AzureCloudDetector(facts)
        is_vm = azure_detector.is_vm()
        self.assertTrue(is_vm)
        is_azure_vm = azure_detector.is_running_on_cloud()
        self.assertFalse(is_azure_vm)

    def test_vm_without_dmi_bios_info(self):
        """
        Test for the case, when MS BIOS does not provide any useful information for our code
        """
        # We will mock facts using simple dictionary
        facts = {}
        azure_detector = azure.AzureCloudDetector(facts)
        is_vm = azure_detector.is_vm()
        self.assertFalse(is_vm)
        is_azure_vm = azure_detector.is_running_on_cloud()
        self.assertFalse(is_azure_vm)


class TestGCPDetector(unittest.TestCase):
    """
    Class used for testing detector of GCP
    """

    def test_gcp_not_vm(self):
        """
        Test for the case, when the machine is host (not virtual machine)
        """
        # We will mock facts using simple dictionary
        facts = {
            'virt.is_guest': False,
            'dmi.bios.version': 'cool hardware company'
        }
        gcp_detector = gcp.GCPCloudDetector(facts)
        is_vm = gcp_detector.is_vm()
        self.assertFalse(is_vm)

    def test_gcp_vm(self):
        """
        Test for the case, when the vm is running on GCP
        """
        # We will mock facts using simple dictionary
        facts = {
            'virt.is_guest': True,
            'virt.host_type': 'kvm',
            'dmi.bios.version': 'Google',
            'dmi.bios.vendor': 'Google'
        }
        gcp_detector = gcp.GCPCloudDetector(facts)
        is_vm = gcp_detector.is_vm()
        self.assertTrue(is_vm)
        is_gcp_vm = gcp_detector.is_running_on_cloud()
        self.assertTrue(is_gcp_vm)

    def test_vm_not_on_gcp_cloud(self):
        """
        Test for the case, when the vm is not running on GCP
        """
        # We will mock facts using simple dictionary
        facts = {
            'virt.is_guest': True,
            'virt.host_type': 'kvm',
            'dmi.bios.version': '1.0',
            'dmi.bios.vendor': 'Foo'
        }
        gcp_detector = gcp.GCPCloudDetector(facts)
        is_vm = gcp_detector.is_vm()
        self.assertTrue(is_vm)
        is_gcp_vm = gcp_detector.is_running_on_cloud()
        self.assertFalse(is_gcp_vm)


AWS_METADATA = """
{
  "accountId" : "012345678900",
  "architecture" : "x86_64",
  "availabilityZone" : "eu-central-1b",
  "billingProducts" : [ "bp-0124abcd" ],
  "devpayProductCodes" : null,
  "marketplaceProductCodes" : null,
  "imageId" : "ami-0123456789abcdeff",
  "instanceId" : "i-abcdef01234567890",
  "instanceType" : "m5.large",
  "kernelId" : null,
  "pendingTime" : "2020-02-02T02:02:02Z",
  "privateIp" : "12.34.56.78",
  "ramdiskId" : null,
  "region" : "eu-central-1",
  "version" : "2017-09-30"
}
"""

AWS_TOKEN = "ABCDEFGHIJKLMNOPQRSTVWXYZabcdefghijklmnopqrstvwxyz0123=="


class TestAWSCollector(unittest.TestCase):
    """
    Test case for AWSCloudCollector
    """

    def setUp(self):
        """
        Patch communication with metadata provider
        """
        requests_patcher = patch('rhsmlib.cloud.providers.aws.requests')
        self.requests_mock = requests_patcher.start()
        self.addCleanup(requests_patcher.stop)

    def test_get_metadata_from_server_imds_v1(self):
        """
        Test the case, when metadata are obtained from server using IMDSv1
        """
        mock_result = Mock()
        mock_result.status_code = 200
        mock_result.text = AWS_METADATA
        self.requests_mock.get = Mock(return_value=mock_result)
        aws_collector = aws.AWSCloudCollector()
        # Mock that no metadata cache exists
        aws_collector._get_metadata_from_cache = Mock(return_value=None)
        metadata = aws_collector.get_metadata()
        self.assertEqual(metadata, AWS_METADATA)

    def test_get_metadata_from_server_imds2(self):
        """
        Test the case, when metadata are obtained from server using IMDSv2
        """

        def get_only_imds_v2_is_supported(url, headers, *args, **kwargs):
            """
            Mock result, when we try to get metadata using GET method against
            AWS metadata provider. This mock is for the case, when only IMDSv2
            is supported by instance.
            :param url: URL
            :param headers: HTTP headers
            :param args: other position argument
            :param kwargs: other keyed argument
            :return: Mock with result
            """
            if url == aws.AWSCloudCollector.CLOUD_PROVIDER_METADATA_URL:
                if 'X-aws-ec2-metadata-token' in headers.keys():
                    if headers['X-aws-ec2-metadata-token'] == AWS_TOKEN:
                        mock_result = Mock()
                        mock_result.status_code = 200
                        mock_result.text = AWS_METADATA
                    else:
                        mock_result = Mock()
                        mock_result.status_code = 400
                        mock_result.text = 'Error: Invalid metadata token provided'
                else:
                    mock_result = Mock()
                    mock_result.status_code = 400
                    mock_result.text = 'Error: IMDSv1 is not supported on this instance'
            else:
                mock_result = Mock()
                mock_result.status_code = 400
                mock_result.text = 'Error: Invalid URL'
            return mock_result

        def put_imds_v2_token(url, headers, *args, **kwargs):
            """
            Mock getting metadata token using PUT method against AWS metadata provider
            :param url: URL
            :param headers: HTTP header
            :param args: other position arguments
            :param kwargs: other keyed arguments
            :return: Mock with response
            """
            if url == aws.AWSCloudCollector.CLOUD_PROVIDER_TOKEN_URL:
                if 'X-aws-ec2-metadata-token-ttl-seconds' in headers:
                    mock_result = Mock()
                    mock_result.status_code = 200
                    mock_result.text = AWS_TOKEN
                else:
                    mock_result = Mock()
                    mock_result.status_code = 400
                    mock_result.text = 'Error: TTL for token not specified'
            else:
                mock_result = Mock()
                mock_result.status_code = 400
                mock_result.text = 'Error: Invalid URL'
            return mock_result

        self.requests_mock.get = get_only_imds_v2_is_supported
        self.requests_mock.put = put_imds_v2_token

        aws_collector = aws.AWSCloudCollector()
        # Mock that no metadata cache exists
        aws_collector._get_metadata_from_cache = Mock(return_value=None)
        # Mock that no token cache exists
        aws_collector._get_token_from_cache_file = Mock(return_value=None)
        # Mock writing token to cache file
        aws_collector._write_token_to_cache_file = Mock()

        metadata = aws_collector.get_metadata()
        self.assertEqual(metadata, AWS_METADATA)


class TestCloudUtils(unittest.TestCase):
    """
    Class for testing rhsmlib.cloud.utils module
    """
    def setUp(self):
        """
        Set up two mocks that are used in all tests
        """
        host_collector_patcher = patch('rhsmlib.cloud.utils.HostCollector')
        self.host_collector_mock = host_collector_patcher.start()
        self.host_fact_collector_instance = Mock()
        self.host_collector_mock.return_value = self.host_fact_collector_instance
        self.addCleanup(host_collector_patcher.stop)

        hardware_collector_patcher = patch('rhsmlib.cloud.utils.HardwareCollector')
        self.hardware_collector_mock = hardware_collector_patcher.start()
        self.hw_fact_collector_instance = Mock()
        self.hardware_collector_mock.return_value = self.hw_fact_collector_instance
        self.addCleanup(hardware_collector_patcher.stop)

    def test_detect_cloud_provider_aws(self):
        """
        Test the case, when detecting of aws works as expected
        """
        host_facts = {
            'virt.is_guest': True,
            'virt.host_type': 'kvm'
        }
        hw_facts = {
            'dmi.bios.vendor': 'Amazon EC2'
        }
        self.host_fact_collector_instance.get_all.return_value = host_facts
        self.hw_fact_collector_instance.get_all.return_value = hw_facts
        detected_clouds = detect_cloud_provider()
        self.assertEqual(detected_clouds, ['aws'])

    def test_detect_cloud_provider_aws_heuristics(self):
        """
        Test the case, when detecting of aws does not work using strong signs, but it is necessary
        to use heuristics method
        """
        host_facts = {
            'virt.is_guest': True,
            'virt.host_type': 'kvm'
        }
        hw_facts = {
            'dmi.bios.vendor': 'AWS',
            'dmi.bios.version': '1.0'
        }
        self.host_fact_collector_instance.get_all.return_value = host_facts
        self.hw_fact_collector_instance.get_all.return_value = hw_facts
        detected_clouds = detect_cloud_provider()
        self.assertEqual(detected_clouds, ['aws', 'gcp'])

    def test_detect_cloud_provider_gcp(self):
        """
        Test the case, when detecting of gcp works as expected
        """
        host_facts = {
            'virt.is_guest': True,
            'virt.host_type': 'kvm'
        }
        hw_facts = {
            'dmi.bios.vendor': 'Google',
            'dmi.bios.version': 'Google'
        }
        self.host_fact_collector_instance.get_all.return_value = host_facts
        self.hw_fact_collector_instance.get_all.return_value = hw_facts
        detected_clouds = detect_cloud_provider()
        self.assertEqual(detected_clouds, ['gcp'])

    def test_detect_cloud_provider_gcp_heuristics(self):
        """
        Test the case, when detecting of gcp does not work using strong signs, but it is necessary
        to use heuristics method
        """
        host_facts = {
            'virt.is_guest': True,
            'virt.host_type': 'kvm'
        }
        hw_facts = {
            'dmi.bios.vendor': 'Foo Company',
            'dmi.bios.version': '1.0',
            'dmi.chassis.asset_tag': 'Google Cloud'
        }
        self.host_fact_collector_instance.get_all.return_value = host_facts
        self.hw_fact_collector_instance.get_all.return_value = hw_facts
        detected_clouds = detect_cloud_provider()
        self.assertEqual(detected_clouds, ['gcp', 'aws'])

    def test_detect_cloud_provider_azure(self):
        """
        Test the case, when detecting of azure works as expected
        """
        host_facts = {
            'virt.is_guest': True,
            'virt.host_type': 'hyperv',
        }
        hw_facts = {
            'dmi.bios.vendor': 'Foo company',
            'dmi.bios.version': '1.0',
            'dmi.chassis.asset_tag': '7783-7084-3265-9085-8269-3286-77'
        }
        self.host_fact_collector_instance.get_all.return_value = host_facts
        self.hw_fact_collector_instance.get_all.return_value = hw_facts
        detected_clouds = detect_cloud_provider()
        self.assertEqual(detected_clouds, ['azure'])

    def test_detect_cloud_provider_azure_heuristics(self):
        """
        Test the case, when detecting of azure does not work using strong signs, but it is necessary
        to use heuristics method
        """
        host_facts = {
            'virt.is_guest': True,
            'virt.host_type': 'hyperv',
        }
        hw_facts = {
            'dmi.bios.vendor': 'Microsoft',
            'dmi.bios.version': '1.0',
            'dmi.system.manufacturer': 'Google',
            'dmi.chassis.manufacturer': 'Amazon'
        }
        self.host_fact_collector_instance.get_all.return_value = host_facts
        self.hw_fact_collector_instance.get_all.return_value = hw_facts
        detected_clouds = detect_cloud_provider()
        self.assertEqual(detected_clouds, ['azure', 'gcp', 'aws'])
