This Python code is for the Lambda function that performs the auto-remediation. It parses the GuardDuty finding from the EventBridge event, extracts the compromised instance ID, and stops the instance.

import boto3
import json
import os

# Initialize the EC2 client
ec2 = boto3.client('ec2')

def lambda_handler(event, context):
    """
    This Lambda function is triggered by an EventBridge rule for GuardDuty findings.
    It extracts the EC2 instance ID from the finding and stops the instance.
    """
    print("Received GuardDuty finding:")
    print(json.dumps(event))

    try:
        # Extract the instance ID from the GuardDuty finding details
        # The path to the instance ID may vary slightly based on the finding type
        instance_id = event['detail']['resource']['instanceDetails']['instanceId']
        
        print(f"Attempting to stop compromised instance: {instance_id}")

        # Stop the EC2 instance
        response = ec2.stop_instances(
            InstanceIds=[instance_id],
            DryRun=False # Set to True to test permissions without actually stopping it
        )
        
        print(f"Successfully sent stop command for instance {instance_id}.")
        print(json.dumps(response))
        
        return {
            'statusCode': 200,
            'body': json.dumps(f'Successfully initiated stop for instance {instance_id}')
        }

    except KeyError:
        print("Could not find instance ID in the event. The finding may not be related to an EC2 instance.")
        return {'statusCode': 400, 'body': 'No EC2 instance ID found in the event.'}
    except Exception as e:
        print(f"An error occurred: {str(e)}")
        return {'statusCode': 500, 'body': f'Error stopping instance: {str(e)}'}
