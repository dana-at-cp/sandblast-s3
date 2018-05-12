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
# version: 0.1
# ~~~~~~~~~~~~~~~~~~~~

import boto3
import hashlib
import json
import os
import requests
import time
import uuid

def is_endpoint_subscribed_to_topic(client, topicArn, endpoint):
    print('Entering is_endpoint_subscribed_to_topic()')
    result = False
    r = client.list_subscriptions_by_topic(TopicArn=topicArn)
    for sub_data in r['Subscriptions']:
        if sub_data['Endpoint'] == endpoint:
            result = True
            break
    print('Leaving is_endpoint_subscribed_to_topic()')
    return result

def subscribe_endpoints_to_topic(client, topicArn):
    print('Entering subscribe_endpoints_to_topic()')
    endpoints = [x.strip() for x in os.environ['SNS_EMAIL_ENDPOINTS'].split(',')]
    for endpoint in endpoints:
        if is_endpoint_subscribed_to_topic(client, topicArn, endpoint):
            print('Endpoint is already subscribed to topic: {}'.format(endpoint))
        else:
            r = client.subscribe(
                TopicArn=topicArn,
                Protocol='email',
                Endpoint=endpoint
            )
            print('r: {}'.format(r))
    print('Leaving subscribe_endpoints_to_topic()')

def update_sns_topic(message):
    print('Entering update_sns_topic()')
    client = boto3.client('sns', region_name='us-east-1')
    r = client.create_topic(Name='cp_sandblast_api_demo_status')
    print('r: {}'.format(r))
    print('TopicArn: {}'.format(r['TopicArn']))
    topicArn = r['TopicArn']
    subscribe_endpoints_to_topic(client, topicArn)
    r = client.publish(
        TopicArn=topicArn,
        Message=message,
        Subject='Check Point SandBlast API Demo Alert'
    )
    print('Leaving update_sns_topic()')

def is_size_ok(size):
    print('Entering is_size_ok()')
    result = True
    max_size = os.environ['MAX_FILE_SIZE_BYTES']
    if size > max_size:
        print('File size exceeds maximum value: {} > {}'.format(size, max_size))
        result = False
    print('Leaving is_size_ok()')
    return result

def gen_md5sum(file):
    print('Entering md5sum()')
    hash_md5 = hashlib.md5()
    with open(file, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    print('Leaving md5sum()')
    return hash_md5.hexdigest()

def merge_dicts(x, y):
    z = x.copy()
    z.update(y)
    return z

def is_found(status):
    result = False
    # FOUND/1001
    if status['code'] == 1001:
        result = True
    return result

def is_pending(status):
    result = False
    # PENDING/1003
    if status['code'] == 1003:
        result = True
    return result

def sb_api_download_file(id):
    print('Entering sb_api_download_file()')
    service = "https://te.checkpoint.com/tecloud/api/v1/file/download"
    headers = { 'Authorization': os.environ['TE_API_KEY'] }
    params = {"id": id}
    download_path = '/tmp/{}.bin'.format(uuid.uuid4())
    r = requests.get(service, headers=headers, params=params)
    if r.status_code == requests.codes.ok:
        with open(download_path,"w") as report:
            report.write(r.content)
        print('Successfully downloaded file with id: {}'.format(id))
        print('Download path: {}'.format(download_path))
    else:
        r.raise_for_status()
    print('Leaving sb_api_download_file()')
    return download_path

def sb_api_upload_file(file):
    print('Entering sb_api_upload_file()')
    result = False
    service = "https://te.checkpoint.com/tecloud/api/v1/file/upload"
    headers = { 'Authorization': os.environ['TE_API_KEY'] }
    request = { 'request': { 'file_name': file, 'features': ['te'], 'te': { 'reports': ["pdf"] } } }
    files = { 'file': open(file,'rb'), 'request': json.dumps(request) }
    r = requests.post(service, headers=headers, files=files)
    if r.status_code == requests.codes.ok:
        rText = json.loads(r.text)
        print(json.dumps(rText, indent=4, sort_keys=True))
        result = True
    else:
        r.raise_for_status()
    print('Leaving sb_api_upload_file()')
    return result

def sb_api_file_query(md5sum):
    print('Entering sb_api_file_query()')
    result = { 'te_combined_verdict': 'unknown' }
    service = "https://te.checkpoint.com/tecloud/api/v1/file/query"
    headers = { 'Authorization': os.environ['TE_API_KEY'] }
    data = { "request": [ { "md5": md5sum, "features": ["te"], 'te': { 'reports': ["pdf"] } } ] }
    r = requests.post(service, headers=headers, data=json.dumps(data))
    if r.status_code == requests.codes.ok:
        rText = json.loads(r.text)
        print json.dumps(rText, indent=4, sort_keys=True)
        status = rText['response'][0]['te']['status']
        print('status: {}'.format(status))
        result = merge_dicts(result, { 'status': status })
        images = rText['response'][0]['te']['images']
        print('images: {}'.format(images))
        result = merge_dicts(result, { 'images': images })
        if is_found(status):
            te_combined_verdict = rText['response'][0]['te']['combined_verdict']
            result = merge_dicts(result, { 'te_combined_verdict': te_combined_verdict, 'source': 'sbapi' })
    else:
        r.raise_for_status()
    print('result: {}'.format(result))
    print('Leaving sb_api_file_query()')
    return result

def is_in_clean_cache(md5sum, s3_client):
    print('Entering is_in_clean_cache()')
    clean_bucket = os.environ['CLEAN_S3_BUCKET']
    result = is_key_prefix_in_bucket(s3_client, clean_bucket, md5sum)
    print('result: {}'.format(result))
    print('Leaving is_in_clean_cache()')
    return result

def is_in_infected_cache(md5sum, s3_client):
    print('Entering is_in_infected_cache()')
    infected_bucket = os.environ['INFECTED_S3_BUCKET']
    result = is_key_prefix_in_bucket(s3_client, infected_bucket, md5sum)
    print('result: {}'.format(result))
    print('Leaving is_in_infected_cache()')
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
    print('Entering is_key_prefix_in_bucket()')
    found = False
    print('Searching bucket: {}'.format(bucket))
    print('Looking for key prefix: {}'.format(prefix))
    start = time.clock()
    for key in get_s3_keys(s3_client, bucket, prefix):
        print('Found match: {}'.format(key))
        found = True
        break
    stop = time.clock()
    print('Search completed in {} s'.format(stop - start))
    print('Leaving is_key_prefix_in_bucket()')
    return found

def get_pdf_reports(pdf_report_ids):
    print('Entering get_pdf_reports()')
    pdf_reports = []
    for pdf_report_id in pdf_report_ids:
        file_path = sb_api_download_file(pdf_report_id)
        pdf_reports.append({ 'id': pdf_report_id, 'file_path': file_path })
    print('pdf_reports: {}'.format(pdf_reports))
    print('Leaving get_pdf_reports()')
    return pdf_reports

def get_pdf_report_ids(images):
    print('Entering get_pdf_report_ids()')
    pdf_report_ids = []
    for image in images:
        pdf_report_ids.append(image['report']['pdf_report'])
    print('pdf_report_ids: {}'.format(pdf_report_ids))
    print('Leaving get_pdf_report_ids()')
    return pdf_report_ids

def get_verdict(file, md5sum, s3):
    print('Entering get_verdict()')
    result = {}
    if is_in_clean_cache(md5sum, s3):
        print('Found hit in clean cache')
        found = True
        result = { 'te_combined_verdict': 'benign', 'source': 's3cache' }
    elif is_in_infected_cache(md5sum, s3):
        print('Found hit in infected cache')
        found = True
        result = { 'te_combined_verdict': 'malicious', 'source': 's3cache' }
    else:
        found = False
        file_uploaded = False
        while not found:
            r = sb_api_file_query(md5sum)
            if is_found(r['status']):
                result = r
                found = True
            elif is_pending(r['status']) or file_uploaded:
                print('Threat emulation results pending ...')
                print('Going to sleep for 10 seconds')
                time.sleep(10)
            else:
                print('Uploading file via SandBlast API')
                file_uploaded = sb_api_upload_file(file)
                print('Going to sleep for 30 seconds')
                time.sleep(30)
    print('result: {}'.format(result))
    print('Leaving get_verdict()')
    return result

def lambda_handler(event, context):
    print('Entering lambda_handler()')
    s3 = boto3.client('s3')
    for record in event['Records']:
        bucket = record['s3']['bucket']['name']
        key = record['s3']['object']['key']
        size = record['s3']['object']['size']
        print('Bucket: {}\nKey: {}\nSize: {}'.format(bucket, key, size))
        if is_size_ok(size):
            download_path = '/tmp/{}'.format(key)
            s3.download_file(bucket, key, download_path)
            s3.delete_object(Bucket=bucket, Key=key)
            md5sum = gen_md5sum(download_path)
            do_upload = True
            upload_bucket = os.environ['CLEAN_S3_BUCKET']
            r = get_verdict(download_path, md5sum, s3)
            verdict = r['te_combined_verdict']
            verdict_source = r['source']
            sns_msg = ''
            if verdict == 'benign':
                sns_msg += 'File is clean: {}\n\nSource: {}\n\n'.format(key, verdict_source)
            elif verdict == 'malicious':
                upload_bucket = os.environ['INFECTED_S3_BUCKET']
                sns_msg += 'File is infected: {}\n\nSource: {}\n\n'.format(key, verdict_source)
                reports_bucket = os.environ['REPORTS_S3_BUCKET']
                print('Reports bucket: {}'.format(reports_bucket))
                sns_msg += 'Threat emulation reports:\n\n'
                if verdict_source == 'sbapi':
                    pdf_reports = get_pdf_reports(get_pdf_report_ids(r['images']))
                    for pdf_report in pdf_reports:
                        report_key = '{}/{}.pdf'.format(md5sum, pdf_report['id'])
                        s3.put_object(
                            ACL='public-read',
                            Body=open(pdf_report['file_path'], 'rb'),
                            Bucket=reports_bucket,
                            Key=report_key
                        )
                        report_url = '{}/{}/{}'.format(s3.meta.endpoint_url, reports_bucket, report_key)
                        sns_msg += report_url + '\n\n'
                elif verdict_source == 's3cache':
                    for report_key in get_s3_keys(s3, reports_bucket, md5sum):
                        report_url = '{}/{}/{}'.format(s3.meta.endpoint_url, reports_bucket, report_key)
                        sns_msg += report_url + '\n\n'
                else:
                    sns_msg += 'None\n\n'
            else:
                do_upload = False
                sns_msg += 'Unknown verdict: {}\n\n'.format(verdict)
            if do_upload:
                sns_msg += 'Destination bucket: {}\n\n'.format(upload_bucket)
                new_key = '{}-{}'.format(md5sum, key)
                s3.upload_file(download_path, upload_bucket, new_key)
                sns_msg += 'Uploaded file to destination bucket: {}\n\n'.format(new_key)
            print('sns_msg: {}'.format(sns_msg))
            update_sns_topic(sns_msg)
    print('Leaving lambda_handler()')
    return 'Hello, World!'
