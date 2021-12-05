#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from '@aws-cdk/core';
import { AwsEksDeploymentArchitectureCdkStack } from '../lib/aws-eks-deployment-architecture';

const app = new cdk.App();
new AwsEksDeploymentArchitectureCdkStack(app, 'AwsEksDeploymentArchitectureCdkStack');
