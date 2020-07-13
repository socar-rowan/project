"""

Lambda function that receives an S3 event for a cloudtrail log file

Downloads the file from the event, insert its json contents into elasticsearch

Profit!



Signed URL code taken from AWS docs and adapted for this script

http://docs.aws.amazon.com/general/latest/gr/sigv4-signed-request-examples.html

"""



import json

import gzip

import requests

import datetime

import hashlib

import hmac

import boto3

import os

import tempfile



##########################################################################

# variables to be set in the lambda environment



# no https nor trailing slash in this one, just the full hostname of your elasticsearch endpoint

host = os.environ.get('ES_HOST')

region = os.environ.get('AWS_REGION')

# if indexname is set to 'foo' then it will write to an index called

# foo-YYYY-MM-DD

indexname =  os.environ.get('ES_INDEX')

if( indexname == None ):

    indexname = "cloudtrail"

##########################################################################

access_key = os.environ.get('AWS_ACCESS_KEY_ID')

secret_key = os.environ.get('AWS_SECRET_ACCESS_KEY')

session_token = os.environ.get('AWS_SESSION_TOKEN')

# variables that you should'nt have to change, ever :)

method = 'POST'

service = 'es'

content_type = 'application/json'



# functions used in the aws signed url

def sign(key, msg):

    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()



def get_signature_key(key, date_stamp, region_name, service_name):

    k_date = sign(('AWS4' + key).encode('utf-8'), date_stamp)

    k_region = sign(k_date, region_name)

    k_service = sign(k_region, service_name)

    k_signing = sign(k_service, 'aws4_request')

    return k_signing



# defines a s3 boto client

s3 = boto3.client('s3')



# main function, started by lambda

def lambda_handler(event, context):

    # attribute bucket and file name/path to variables

    bucket = event['Records'][0]['s3']['bucket']['name']

    key = event['Records'][0]['s3']['object']['key']



    # Minimal error handling

    if( bucket == None or key == None ):

        return



    # where to save the downloaded file

    s3obj = tempfile.NamedTemporaryFile(mode='w+b',delete=False)



    # downloads file to above path

    s3.download_fileobj(bucket, key, s3obj)



    s3obj.close()

    gzfile = gzip.open(s3obj.name, "r")



    # loads contents of the Records key into variable (our actual cloudtrail log entries!)

    response = json.loads(gzfile.readlines()[0])



    """ I do dumb stuff in my account and I have more than just CloudTrail

        in my S3 bucket. There's CloudTrail Digests, and some Config snapshots

        that drop in as well. So if I see an S3 object and it isn't a CloudTrail

        message, I figure that out here and ignore it.

    """

    if( "Records" not in response ):

        print( "Not CloudTrail. Exiting." )

        return



    eventcount = 1

    # loops over the events in the json

    for i in response["Records"]:

        # This is a place you could filter out some events you don't care

        # about. I'm leaving one in as an example.

        if ( i["eventName"] == "describeInstanceHealth" ):

            continue

        

        # I find the apiVersion causes problems with the index mapping.

        # The -right- solution would be to solve it with a proper mapping.

        # Frankly, I never use apiVersion in any of my searches. I really

        # don't care. So I'm just deleting it.

        i.pop( 'apiVersion', None )



        # adds @timestamp field = time of the event

        i["@timestamp"] = i["eventTime"]



        # removes .aws.amazon.com from eventsources

        i["eventSource"] = i["eventSource"].split(".")[0]

        data = json.dumps(i).encode('utf-8')

#        print( "data:\n---\n{}\n---\n".format( data ))



        # defines correct index name based on eventTime, so we have an index for each day on ES

        event_date = i["eventTime"].split("T")[0]



        canonical_uri = '/' + indexname + '-' + event_date + '/_doc'

        # url endpoint for our ES cluster

        url = 'https://' + host + canonical_uri

#        print( "Event {} url : {}\n".format(eventcount, url))



        # aws signed url stuff - for comments on this check their example page linked on top comment

        t = datetime.datetime.utcnow()

        amz_date = t.strftime('%Y%m%dT%H%M%SZ')

        date_stamp = t.strftime('%Y%m%d')

        canonical_querystring = ''

        canonical_headers = 'content-type:' + content_type + '\n' + \

                            'host:' + host + '\n' + \

                            'x-amz-date:' + amz_date + '\n'

        signed_headers = 'content-type;host;x-amz-date'

        payload_hash = hashlib.sha256(data).hexdigest()

        canonical_request = method + '\n' + \

                            canonical_uri + '\n' + \

                            canonical_querystring + '\n' + \

                            canonical_headers + '\n' + \

                            signed_headers + '\n' + \

                            payload_hash

        algorithm = 'AWS4-HMAC-SHA256'

        credential_scope = date_stamp + '/' + region + '/' + service + '/' + 'aws4_request'

        string_to_sign = algorithm + '\n' + \

                         amz_date + '\n' + \

                         credential_scope + '\n' + \

                         hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()

        signing_key = get_signature_key(secret_key, date_stamp, region, service)

        signature = hmac.new(signing_key, string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()

        authorization_header = algorithm + ' ' + \

                               'Credential=' + access_key + '/' + credential_scope + ', ' + \

                               'SignedHeaders=' + signed_headers + ', ' + \

                               'Signature=' + signature

        headers = {'Content-Type':content_type,

                   'X-Amz-Date':amz_date,

                   'Authorization':authorization_header, 'X-Amz-Security-Token': session_token}



        # sends the json to elasticsearch

        req = requests.post(url, data=data, headers=headers)

#        print( "Attempt 0 status code: {}".format(req.status_code))

#        print( "response:\n---\n{}\n---\n".format( req.text ))



        retry_counter = 1



        """

        if we fail for some reason we will retry 3 times

        you will most likely have errors if you're copying a huge ammount of logs from an old bucket

        to your new one.



        For normal usage you shouldnt have to worry about this.

        I got it in production with 90 aws accounts pointing to the same bucket,

        and a pair of m3.mediums on the ES cluster, with 0 errors.



        I dont raise an exception on errors to not miss all the other entries in the file, or risk repeating any

        inserts done before the error.

        """

        # if our status code is not successfull, and our retry counter is less than 4

        while (req.status_code != 201) and (retry_counter < 4):

#            print( "Got code {}. Retrying {} of 3".format( req.status_code, retry_counter) )



            # send the data to ES again

            req = requests.post(url, data=data, headers=headers)



#            print( "status code: {}".format(req.status_code))

            retry_counter += 1

        eventcount +=1



    s3obj.close()

    os.unlink(s3obj.name)

    print( "{} events in {}".format(eventcount, s3obj.name) )