#!/usr/bin/env node
import * as cdk from 'aws-cdk-lib';
import { AppRunnerStack } from '../lib/app-runner-stack';

const app = new cdk.App();
new AppRunnerStack(app, 'app-runner-stack', {
});

app.synth();
