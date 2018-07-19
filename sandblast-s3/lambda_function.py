# -*- coding: utf-8 -*-

# Copyright 2018 Dana James Traversie and Check Point Software Technologies, Ltd. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# file: https://github.com/dana-at-cp/sandblast-s3/sandblast-s3/lambda_function.py
# version: 0.2
# ~~~~~~~~~~~~~~~~~~~~

import boto3
import hashlib
import json
import os
import requests
import time
import uuid

supported_features = { 'av', 'te', 'extraction' }
enabled_features = []
tx_result_success = 'CP_EXTRACT_RESULT_SUCCESS'
tx_forward_done = False
tx_forward_error = False
tx_forward_not_found = False
tx_forward_file_name = ''

def is_endpoint_subscribed_to_topic(client, topicArn, endpoint):
    result = False
    r = client.list_subscriptions_by_topic(TopicArn=topicArn)
    for sub_data in r['Subscriptions']:
        if sub_data['Endpoint'] == endpoint:
            result = True
            break
    return result

def subscribe_endpoints_to_topic(client, topicArn):
    endpoints = [x.strip() for x in os.environ['SNS_EMAIL_ENDPOINTS'].split(',')]
    for endpoint in endpoints:
        if not is_endpoint_subscribed_to_topic(client, topicArn, endpoint):
            r = client.subscribe(
                TopicArn=topicArn,
                Protocol='email',
                Endpoint=endpoint
            )

def update_sns_topic(message):
    client = boto3.client('sns', region_name='us-east-1')
    r = client.create_topic(Name='cpSandBlastS3_notifications')
    topicArn = r['TopicArn']
    subscribe_endpoints_to_topic(client, topicArn)
    r = client.publish(
        TopicArn=topicArn,
        Message=message,
        Subject='Check Point SandBlast S3 Notification'
    )

def get_forward_clean_bucket():
    return os.environ.get('FORWARD_CLEAN_S3_BUCKET')

def is_forward_clean_bucket_defined():
    result = False
    if get_forward_clean_bucket() is not None:
        result = True
    return result

def get_max_file_size():
    max_size = os.environ.get('MAX_FILE_SIZE_BYTES')
    if max_size is None:
        max_size = 10240000
    return max_size

def is_size_ok(size):
    result = True
    max_size = get_max_file_size()
    if size > max_size:
        result = False
    return result

def gen_md5sum(file):
    hash_md5 = hashlib.md5()
    with open(file, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

def merge_dicts(x, y):
    z = x.copy()
    z.update(y)
    return z

def get_sbapi_resp_status(sbapi_resp):
    resp_text = get_sbapi_resp_text(sbapi_resp)
    resp_status = resp_text['status']
    return resp_status

def is_found(sbapi_resp_status):
    result = False
    # FOUND/1001
    if sbapi_resp_status['code'] == 1001:
        result = True
    return result

def is_pending(sbapi_resp_status):
    result = False
    # PENDING/1003
    if sbapi_resp_status['code'] == 1003:
        result = True
    return result

def is_not_found(sbapi_resp_status):
    result = False
    # NOT_FOUND/1004
    if sbapi_resp_status['code'] == 1004:
        result = True
    return result

def get_enabled_features_raw():
    return os.environ.get('ENABLED_FEATURES')

def are_enabled_features_defined():
    result = False
    if get_enabled_features_raw() is not None:
        result = True
    return result

def get_enabled_features():
    global enabled_features
    if not enabled_features:
        if not are_enabled_features_defined():
            enabled_features.append('te')
        else:
            raw_features = [x.strip() for x in get_enabled_features_raw().split(',')]
            for raw_feature in raw_features:
                if raw_feature in supported_features:
                    enabled_features.append(raw_feature)
    return enabled_features

def is_only_av_enabled():
    result = False
    if is_av_enabled():
        if not is_tx_enabled() and not is_te_enabled():
            result = True
    return result

def is_only_tx_enabled():
    result = False
    if is_tx_enabled():
        if not is_av_enabled() and not is_te_enabled():
            result = True
    return result

def is_av_enabled():
    result = False
    if 'av' in get_enabled_features():
        result = True
    return result

def is_tx_enabled():
    result = False
    if 'extraction' in get_enabled_features():
        result = True
    return result

def is_te_enabled():
    result = False
    if 'te' in get_enabled_features():
        result = True
    return result

def sbapi_download_file(id):
    service = "https://te.checkpoint.com/tecloud/api/v1/file/download"
    headers = { 'Authorization': os.environ['TE_API_KEY'] }
    params = {"id": id}
    download_path = '/tmp/{}.bin'.format(uuid.uuid4())
    r = requests.get(service, headers=headers, params=params)
    if r.status_code == requests.codes.ok:
        with open(download_path,"w") as f:
            f.write(r.content)
    else:
        r.raise_for_status()
    return download_path

def sbapi_upload_file(file):
    service = "https://te.checkpoint.com/tecloud/api/v1/file/upload"
    headers = { 'Authorization': os.environ['TE_API_KEY'] }
    request = { 'request': { 'file_name': os.path.basename(file), 'features': get_enabled_features(), 'te': { 'reports': ["pdf"] } } }
    files = { 'file': open(file,'rb'), 'request': json.dumps(request) }
    r = requests.post(service, headers=headers, files=files)
    if not r.status_code == requests.codes.ok:
        r.raise_for_status()
    return r

def sbapi_file_query(md5sum):
    service = "https://te.checkpoint.com/tecloud/api/v1/file/query"
    headers = { 'Authorization': os.environ['TE_API_KEY'] }
    data = { "request": [ { "md5": md5sum, "features": get_enabled_features(), 'te': { 'reports': ["pdf"] } } ] }
    r = requests.post(service, headers=headers, data=json.dumps(data))
    if not r.status_code == requests.codes.ok:
        r.raise_for_status()
    return r

def get_sbapi_resp_text(sbapi_resp):
    resp_text = json.loads(sbapi_resp.text)
    try:
        resp_text = resp_text['response'][0]
    except KeyError:
        resp_text = resp_text['response']
    return resp_text

def forward_tx_scrubbed_file(sbapi_resp):
    global tx_forward_done
    global tx_forward_error
    global tx_forward_not_found
    global tx_forward_file_name
    r_text = get_sbapi_resp_text(sbapi_resp)
    tx = r_text['extraction']
    if is_found(tx['status']):
        extract_result = tx['extract_result']
        if extract_result == tx_result_success:
            scrubbed_file_download_id = tx['extracted_file_download_id']
            scrubbed_file_name = tx['output_file_name']
            download_path = sbapi_download_file(scrubbed_file_download_id)
            s3 = boto3.client('s3')
            s3.upload_file(download_path, get_forward_clean_bucket(), scrubbed_file_name)
            tx_forward_done = True
            tx_forward_error = False
            tx_forward_not_found = False
            tx_forward_file_name = scrubbed_file_name
        else:
            tx_forward_done = False
            tx_forward_error = True
            tx_forward_not_found = False
    elif is_not_found(tx['status']):
        tx_forward_done = False
        tx_forward_error = False
        tx_forward_not_found = True

def is_true_av_match(sbapi_resp_text):
    result = False
    av = sbapi_resp_text['av']
    if is_found(av['status']):
        sig_name = av['malware_info']['signature_name']
        family = av['malware_info']['malware_family']
        type = av['malware_info']['malware_type']
        severity = av['malware_info']['severity']
        confidence = av['malware_info']['confidence']
        if sig_name and family > 0 and type > 0 and severity > 0 and confidence > 0:
            result = True
    return result

def get_av_msg(sbapi_resp_text):
    msg = '***** Antivirus *****\n\n'
    if is_true_av_match(sbapi_resp_text):
        av = sbapi_resp_text['av']
        sig_name = av['malware_info']['signature_name']
        msg += 'Malware signature name: {}\n\n'.format(sig_name)
    else:
        msg += 'No malware signature match.\n\n'
    return msg

def get_extraction_msg(sbapi_resp_text):
    msg = '***** Threat Extraction *****\n\n'
    try:
        tx = sbapi_resp_text['extraction']
        if is_found(tx['status']):
            extract_result = tx['extract_result']
            msg += 'TX result: {}\n\n'.format(extract_result)
            if extract_result == tx_result_success:
                scrubbed_file_download_id = tx['extracted_file_download_id']
                scrubbed_file_name = tx['output_file_name']
                orig_file_ext = tx['extraction_data']['input_extension']
                orig_file_real_ext = tx['extraction_data']['input_real_extension']
                scrub_activity = tx['extraction_data']['scrub_activity']
                msg += 'Scrubbed file name: {}\n\n'.format(scrubbed_file_name)
                msg += 'Scrubbed file download ID: {}\n\n'.format(scrubbed_file_download_id)
                msg += 'Scrub activity: {}\n\n'.format(scrub_activity)
                msg += 'Original file extension: {}\n\n'.format(orig_file_ext)
                msg += 'Original file real extension: {}\n\n'.format(orig_file_real_ext)
    except KeyError:
        print('sbapi_resp_text: {}'.format(sbapi_resp_text))
        raise
    return msg

def get_te_msg(sbapi_resp_text):
    msg = '***** Threat Emulation *****\n\n'
    md5sum = sbapi_resp_text['md5']
    te = sbapi_resp_text['te']
    if is_found(te['status']):
        combined_verdict = te['combined_verdict']
        if combined_verdict == 'benign':
            msg += 'No threats found during emulation\n\n'
        elif combined_verdict == 'malicious':
            msg += 'Threats found during emulation!\n\n'
            s3 = boto3.client('s3')
            reports_bucket = os.environ['REPORTS_S3_BUCKET']
            msg += 'Threat emulation reports:\n\n'
            pdf_reports = get_pdf_reports(get_pdf_report_ids(te['images']))
            for pdf_report in pdf_reports:
                report_key = '{}/{}.pdf'.format(md5sum, pdf_report['id'])
                s3.put_object(
                    ACL='public-read',
                    Body=open(pdf_report['file_path'], 'rb'),
                    Bucket=reports_bucket,
                    Key=report_key
                )
                report_url = '{}/{}/{}'.format(s3.meta.endpoint_url, reports_bucket, report_key)
                msg += report_url + '\n\n'
        else:
            msg += 'Unknown combined verdict: {}'.format(combined_verdict)
    return msg

def build_sbapi_verdict_msg(sbapi_resp):
    msg = ''
    resp_text = get_sbapi_resp_text(sbapi_resp)
    resp_features = resp_text['features']
    if 'av' in resp_features:
        msg += get_av_msg(resp_text)
    if 'te' in resp_features:
        msg += get_te_msg(resp_text)
    if 'extraction' in resp_features:
        msg += get_extraction_msg(resp_text)
    return msg

def is_in_clean_cache(md5sum, s3_client):
    clean_bucket = os.environ['CLEAN_S3_BUCKET']
    result = is_key_prefix_in_bucket(s3_client, clean_bucket, md5sum)
    return result

def is_in_infected_cache(md5sum, s3_client):
    infected_bucket = os.environ['INFECTED_S3_BUCKET']
    result = is_key_prefix_in_bucket(s3_client, infected_bucket, md5sum)
    return result

def get_s3_objects(s3_client, bucket, prefix):
    kwargs = {'Bucket': bucket}
    if isinstance(prefix, str):
        kwargs['Prefix'] = prefix
    while True:
        r = s3_client.list_objects_v2(**kwargs)
        try:
            contents = r['Contents']
        except KeyError:
            return
        for obj in contents:
            key = obj['Key']
            if key.startswith(prefix):
                yield obj
        try:
            kwargs['ContinuationToken'] = r['NextContinuationToken']
        except KeyError:
            break

def get_s3_keys(s3_client, bucket, prefix):
    for obj in get_s3_objects(s3_client, bucket, prefix):
        yield obj['Key']

def is_key_prefix_in_bucket(s3_client, bucket, prefix):
    found = False
    start = time.clock()
    for key in get_s3_keys(s3_client, bucket, prefix):
        found = True
        break
    stop = time.clock()
    return found

def get_pdf_reports(pdf_report_ids):
    pdf_reports = []
    for pdf_report_id in pdf_report_ids:
        file_path = sbapi_download_file(pdf_report_id)
        pdf_reports.append({ 'id': pdf_report_id, 'file_path': file_path })
    return pdf_reports

def get_pdf_report_ids(images):
    pdf_report_ids = []
    for image in images:
        pdf_report_ids.append(image['report']['pdf_report'])
    return pdf_report_ids

def get_cache_verdict(md5sum, s3):
    result = {}
    if is_in_clean_cache(md5sum, s3):
        result = { 'verdict': 'benign', 'msg': 'Matched entry in clean cache.' }
    elif is_in_infected_cache(md5sum, s3):
        msg = 'Matched entry in infected cache.\n\nThreat emulation reports:\n\n'
        reports_bucket = os.environ['REPORTS_S3_BUCKET']
        for report_key in get_s3_keys(s3, reports_bucket, md5sum):
            report_url = '{}/{}/{}'.format(s3.meta.endpoint_url, reports_bucket, report_key)
            msg += report_url + '\n\n'
        result = { 'verdict': 'malicious', 'msg': msg }
    return result

def get_sbapi_verdict(file, md5sum):
    print('Entering get_sbapi_verdict()')
    result = {}
    found = False
    waiting_for_extraction = is_tx_enabled()
    r = sbapi_file_query(md5sum)
    print(get_sbapi_resp_text(r))
    while waiting_for_extraction:
        forward_tx_scrubbed_file(r)
        if tx_forward_done:
            print('Extraction completed')
            waiting_for_extraction = False
        elif tx_forward_error:
            print('Extraction failed')
            waiting_for_extraction = False
        elif tx_forward_not_found:
            print('Uploading file')
            r = sbapi_upload_file(file)
            print(get_sbapi_resp_text(r))
            if is_found(get_sbapi_resp_status(r)):
                forward_tx_scrubbed_file(r)
                waiting_for_extraction = False
        else:
            print('Waiting for extraction')
        if waiting_for_extraction:
            time.sleep(15)
            r = sbapi_file_query(md5sum)
            print(get_sbapi_resp_text(r))
    while not found:
        r_status = get_sbapi_resp_status(r)
        if is_not_found(r_status) and is_only_av_enabled():
            result = { 'verdict': 'benign', 'msg': build_sbapi_verdict_msg(r), 'sbapi_resp_text': get_sbapi_resp_text(r) }
            found = True
        elif is_not_found(r_status):
            print('Uploading file ...')
            r = sbapi_upload_file(file)
            print(get_sbapi_resp_text(r))
            if is_found(get_sbapi_resp_status(r)):
                found = True
        elif is_found(r_status):
            if is_only_tx_enabled():
                result = { 'verdict': 'tx_only', 'msg': build_sbapi_verdict_msg(r), 'sbapi_resp_text': get_sbapi_resp_text(r) }
            else:
                verdict = 'unknown'
                resp_text = get_sbapi_resp_text(r)
                if is_av_enabled():
                    if is_true_av_match(resp_text):
                        verdict = 'malicious'
                if is_te_enabled() and not verdict == 'malicious':
                    verdict = resp_text['te']['combined_verdict']
                result = { 'verdict': verdict, 'msg': build_sbapi_verdict_msg(r), 'sbapi_resp_text': get_sbapi_resp_text(r) }
            found = True
        elif is_pending(r_status):
            print('Results pending ...')
            print('Going to sleep for 15 seconds')
            time.sleep(15)
        else:
            print('Unhandled response ...')
        if not found:
            r = sbapi_file_query(md5sum)
            print(get_sbapi_resp_text(r))
    print(result)
    print('Leaving get_sbapi_verdict()')
    return result

def get_verdict(file, md5sum, s3):
    result = {}
    if not is_tx_enabled():
        result = get_cache_verdict(md5sum, s3)
    if not result:
        result = get_sbapi_verdict(file, md5sum)
        result = merge_dicts(result, { 'source': 'sbapi' })
    else:
        result = merge_dicts(result, { 'source': 's3cache' })
    return result
    
def lambda_handler(event, context):
    s3 = boto3.client('s3')
    for record in event['Records']:
        bucket = record['s3']['bucket']['name']
        key = record['s3']['object']['key']
        size = record['s3']['object']['size']
        print('Processing S3 put event ...\n\n')
        print('Original file: {}\n\nOriginal bucket: {}\n\n'.format(key, bucket))
        if is_size_ok(size):
            download_path = '/tmp/{}'.format(key)
            s3.download_file(bucket, key, download_path)
            md5sum = gen_md5sum(download_path)
            print('Original file md5sum: {}\n\n'.format(md5sum))
            is_clean = True
            do_upload = True
            upload_bucket = os.environ['CLEAN_S3_BUCKET']
            r = get_verdict(download_path, md5sum, s3)
            verdict = r['verdict']
            verdict_source = r['source']
            sns_msg = ''
            if verdict == 'benign':
                sns_msg += 'File is clean: {}\n\nSource: {}\n\n'.format(key, verdict_source)
            elif verdict == 'malicious':
                is_clean = False
                upload_bucket = os.environ['INFECTED_S3_BUCKET']
                sns_msg += 'File is infected: {}\n\nSource: {}\n\n'.format(key, verdict_source)
            elif verdict == 'tx_only':
                sns_msg += 'Only TX enabled'
            else:
                do_upload = False
                sns_msg += 'Unknown verdict: {}\n\n'.format(verdict)
            if do_upload:
                sns_msg += 'Destination bucket: {}\n\n'.format(upload_bucket)
                new_key = '{}-{}'.format(md5sum, key)
                s3.upload_file(download_path, upload_bucket, new_key)
                sns_msg += 'Uploaded file to destination bucket: {}\n\n'.format(new_key)
                if is_forward_clean_bucket_defined():
                    sns_msg += 'Forward clean bucket: {}\n\n'.format(get_forward_clean_bucket())
                    if is_tx_enabled() and tx_forward_done:
                        sns_msg += 'Uploaded scrubbed file to forward clean bucket: {}\n\n'.format(tx_forward_file_name)
                    elif is_tx_enabled() and tx_forward_error:
                        sns_msg += 'Failed to scrub file: {}\n\n'.format(key)
                        if is_clean:
                            s3.upload_file(download_path, get_forward_clean_bucket(), key)
                            sns_msg += 'Uploaded file to forward clean bucket: {}\n\n'.format(key)
                    elif is_clean:
                        s3.upload_file(download_path, get_forward_clean_bucket(), key)
                        sns_msg += 'Uploaded file to forward clean bucket: {}\n\n'.format(key)
                    else:
                        sns_msg += "Could not forward file to clean bucket"
            sns_msg += 'Additional information:\n\n'
            sns_msg += r['msg']
            update_sns_topic(sns_msg)
        else:
            print('Error: File size {} is greater than configured max value {}\n\n'.format(size, get_max_file_size()))
        s3.delete_object(Bucket=bucket, Key=key)
    return 'Hello, World!'
