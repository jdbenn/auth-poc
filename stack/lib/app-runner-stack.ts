import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as ecr from 'aws-cdk-lib/aws-ecr';
import * as apprunner from 'aws-cdk-lib/aws-apprunner'
import * as acm from 'aws-cdk-lib/aws-certificatemanager'
import * as route53 from 'aws-cdk-lib/aws-route53';

export class AppRunnerStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);
    
    const repo = new ecr.Repository(this, 'spring-idp-repo', {
      repositoryName: 'spring-idp-repo',
      removalPolicy: cdk.RemovalPolicy.DESTROY
    });
    
    const role = new cdk.aws_iam.Role(this, 'app-runner-ecr-role', {
      assumedBy: new cdk.aws_iam.ServicePrincipal('build.apprunner.amazonaws.com'),
      managedPolicies: [
        cdk.aws_iam.ManagedPolicy.fromManagedPolicyArn(this,'app-runner-ecr-policy','arn:aws:iam::aws:policy/service-role/AWSAppRunnerServicePolicyForECRAccess')
      ]
    })
    
    new apprunner.CfnService(this, 'spring-idp-app-runner', {
      sourceConfiguration: {
        authenticationConfiguration: {
          accessRoleArn: role.roleArn
        },
        imageRepository: {
          imageIdentifier: `${repo.repositoryUri}:latest`,
          imageRepositoryType: 'ECR',
          imageConfiguration: {
            port: '9000',
            runtimeEnvironmentVariables: [
              { name: 'SPRING_PROFILES_ACTIVE', value: 'default' }
            ]
            
          },
        },
        autoDeploymentsEnabled: true,
      },
      healthCheckConfiguration: {
        protocol: 'HTTP',
        path: '/oauth2/jwks',
        healthyThreshold: 1,
        unhealthyThreshold: 5,
        interval: 10,
        timeout: 5,
      },
      serviceName: 'spring-idp',
    })
  }
}
