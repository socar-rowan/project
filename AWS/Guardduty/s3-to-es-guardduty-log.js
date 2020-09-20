/* Imports */
var AWS = require('aws-sdk');
var connectionClass = require('http-aws-es');
var elasticsearch = require('elasticsearch');
var flatten = require('flat');

/* Globals */

function getTimeStamp() {
    var d = new Date();
    var s =
        leadingZeros(d.getFullYear(), 4) + '-' +
        leadingZeros(d.getMonth() + 1, 2) + '-' +
        leadingZeros(d.getDate(), 2);
    return s;
}

function leadingZeros(n, digits) {
    var zero = '';
    var i = 0;
    n = n.toString();
    if (n.length < digits) {
        for (i = 0; i < digits - n.length; i++)
            zero += '0';
    }
    return zero + n;
}
var today = getTimeStamp() ;

var esDomain = {
    endpoint: 'https://YOUR-DOMAIN-ENDPOINT',
    region: 'ap-northeast-2',
    index: 'guarddutylogs-'+today,
    doctype: 'logs'
};
// today value check
console.log(today)

var s3 = new AWS.S3();
var elasticClient = new elasticsearch.Client({  
    host: esDomain.endpoint,
    log: 'error',
    connectionClass: connectionClass,
    amazonES: {
      credentials: new AWS.EnvironmentCredentials('AWS')
    }
});
/*
 * Add the given document to the ES domain.
 * If all records are successfully added, indicate success to lambda
 * (using the "context" parameter).
 */
function postDocumentToES(bucket, key, context) {
    
    console.log('Bucket : ' + bucket + '  Key: ' + key);
    //var req = new AWS.HttpRequest(endpoint);
	var logdata = "";
	var numDocsAdded = 0;   // Number of log lines added to ES so far
	
	var params = {
  		Bucket: bucket,
  		Key: key
	};	
	
	var getObjectPromise = s3.getObject(params).promise();
	getObjectPromise.then(function(data) {
  		logdata = JSON.parse(data.Body);
		console.log("logdata: " + JSON.stringify(logdata) + " id: " + logdata.id);
		var flattened_data = JSON.stringify(flatten(logdata, { maxDepth: 10 }));
		console.log("flattened data: " + flattened_data);
	
		elasticClient.create({
			index: esDomain.index,
			type: esDomain.doctype,
			id: logdata.id,
			body: flattened_data
		}, function (error, response) {		
			if(error)
				console.log("error : " + error); // Publish the error response
			else
				console.log("response: " + response);
		});
	}).catch(function(err) {
  		console.log(err);
	});	

}
/* Lambda "main": Execution starts here */
exports.handler = function(event, context) {
	
	console.log('Received event: ', JSON.stringify(event, null, 2));

    event.Records.forEach(function(record) {
        var bucket = record.s3.bucket.name;
        var objKey = decodeURIComponent(record.s3.object.key.replace(/\+/g, ' '));
        postDocumentToES(bucket, objKey, context);
    });
}