import boto3
import json
from custom_encoder import CustomEncoder
import logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

dynamodbTableName = 'serverless_table'
dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table(dynamodbTableName)

getMethod = 'GET'
postMethod = 'POST'
patchMethod = 'PATCH'
deleteMethod = 'DELETE'
healthPath = '/health'
productPath = '/product'
productsPath = '/products'

def lambda_handler(event, context):
    try:
        logger.info(event)
        httpMethod = event['httpMethod']
        path = event['path']
        if httpMethod == getMethod and path == healthPath:
            response = buildResponse(200)
        elif httpMethod == getMethod and path == productPath:
            response = getProduct(event['queryStringParameters']['productId'])
        elif httpMethod == getMethod and path == productsPath:
            response = getProducts()
        elif httpMethod == postMethod and path == productPath:
            response = saveProduct(json.loads(event['body']))
        elif httpMethod == patchMethod and path == productPath:
            requestBody = json.loads(event['body'])
            response = modifyProduct(requestBody['productId'], requestBody['updatekey'], requestBody['updateValue'])
        elif httpMethod == deleteMethod and path == productPath:
            requestBody = json.loads(event['body'])
            response = deleteProduct(requestBody['productId'])
        else:
            response = buildResponse(404, 'Not Found')
        return response
    except Exception as e:
        logger.exception('Error in lambda_handler: %s', e)
        return buildResponse(500, errorMessage='Internal server error')


def getProduct(productId):
    try:
        response = table.get_item(
            Key={
                'productId': productId
            }
        )
        if 'Item' in response:
            return buildResponse(200, response['Item'])
        else:
            return buildResponse(404, {'Message': 'productId: %s not found' % productId})
    except Exception as e:
        logger.exception('Error in getProduct: %s', e)
        return buildResponse(500, {'Message': 'Internal server error'})

def getProducts():
    try:
        response = table.scan()
        result = response['Items']

        while 'LastEvaluatedKey' in response:
            response = table.scan(ExclusiveStartKey=response['LastEvaluatedKey'])
            result.extend(response['Items'])

        body = {
            'products': result
        }
        return buildResponse(200, body)
    except Exception as e:
        logger.exception('Error in getProducts: %s', e)
        return buildResponse(500, {'Message': 'Internal server error'})

def saveProduct(requestBody):
    try:
        table.put_item(Item=requestBody)
        body = {
            'Operation': 'SAVE',
            'Message': 'SUCCESS',
            'Item': requestBody
        }
        return buildResponse(200, body)
    except:
         logger.exception('Do your custom error handling here. I am just log it out here!!')

def modifyProduct(productId, updatekey, updateValue):
    try:
        response = table.update_item(
            key={
                'productId': productId
            },
            updateExpression='set %s = :value' % updatekey,
            ExpressionAttributeValues={
                ':value': updateValue
            },
            ReturnValues='UPDATED_NEW'
        )
        body = {
            'Operation': 'UPDATE',
            'Message': 'SUCCESS',
            'updatedAttributes': response
        }
        return buildResponse(200, body)
    except:
         logger.exception('Do your custom error handling here. I am just log it out here!!')

def deleteProduct(productId):
    try:
        resource = table.delete_item(
            key={
                'productId': productId
            },
            ReturnValues='ALL_OLD'
        )
        body = {
            'Operation': 'DELETE',
            'Message': 'SUCCESS',
            'deletedItem': resource
        }
        return buildResponse(200, body)
    except:
         logger.exception('Do your custom error handling here. I am just log it out here!!')


def buildResponse(statusCode, body=None, errorMessage=None):
    response = {
        'statusCode': statusCode,
        'headers': {
            'content-Type': 'application/json',
            'Access-control-Allow-Origin': '*'
        }
    }
    if body is not None:
        response['body'] = json.dumps(body, cls=CustomEncoder)
    if errorMessage is not None:
        response['body'] = json.dumps({'error': errorMessage})
    return response
