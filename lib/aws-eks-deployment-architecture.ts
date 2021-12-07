import * as cdk from '@aws-cdk/core';
import eks = require('@aws-cdk/aws-eks');
import ec2 = require('@aws-cdk/aws-ec2');
import iam = require('@aws-cdk/aws-iam');
import codecommit = require("@aws-cdk/aws-codecommit");
import codebuild = require("@aws-cdk/aws-codebuild");
import codepipeline = require("@aws-cdk/aws-codepipeline");
import codepipeline_actions = require("@aws-cdk/aws-codepipeline-actions");
import ecr = require("@aws-cdk/aws-ecr");
import elb = require('@aws-cdk/aws-elasticloadbalancingv2');
import elasticache = require('@aws-cdk/aws-elasticache');
import rds = require('@aws-cdk/aws-rds');
import yaml = require('js-yaml');
import targets = require("@aws-cdk/aws-events-targets");
import fs = require('fs');


export class AwsEksDeploymentArchitectureCdkStack extends cdk.Stack {
  constructor(scope: cdk.Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    const name = 'game-2048'

    const vpc = new ec2.Vpc(this, 'Vpc', {
        cidr: "10.0.0.0/16",
        maxAzs: 2,
        natGateways: 1,
        subnetConfiguration: [
            {
                name: "PublicSubnet",
                cidrMask: 20,
                subnetType: ec2.SubnetType.PUBLIC
            },
            {
                name: "PrivateSubnet",
                cidrMask: 20,
                subnetType: ec2.SubnetType.PRIVATE_WITH_NAT
            }
        ]
    });

    const mastersRole = new iam.Role(this, 'AdminRole', {
        assumedBy: new iam.AccountRootPrincipal()
    });

    const cluster = new eks.Cluster(this, 'eks-cluster', {
        clusterName: name + '-eks-fargate',
        vpc,
        vpcSubnets: [{ subnetType: ec2.SubnetType.PRIVATE_WITH_NAT }],
        mastersRole,
        defaultCapacity: 0,
        version: eks.KubernetesVersion.V1_21,
        endpointAccess: eks.EndpointAccess.PUBLIC_AND_PRIVATE,
    });

    const nodeGroup = cluster.addAutoScalingGroupCapacity('node-group', {
        instanceType: new ec2.InstanceType('c5.xlarge'),
        maxInstanceLifetime: cdk.Duration.days(7),
        minCapacity: 2,
    })


    // Patch aws-node daemonset to use IRSA via EKS Addons, do before nodes are created
    // https://aws.github.io/aws-eks-best-practices/security/docs/iam/#update-the-aws-node-daemonset-to-use-irsa
    const awsNodeTrustPolicy = new cdk.CfnJson(this, 'aws-node-trust-policy', {
        value: {
          [`${cluster.openIdConnectProvider.openIdConnectProviderIssuer}:aud`]: 'sts.amazonaws.com',
          [`${cluster.openIdConnectProvider.openIdConnectProviderIssuer}:sub`]: 'system:serviceaccount:kube-system:aws-node',
        },
    });
    const awsNodePrincipal = new iam.OpenIdConnectPrincipal(cluster.openIdConnectProvider).withConditions({
        StringEquals: awsNodeTrustPolicy,
    });
    const awsNodeRole = new iam.Role(this, 'aws-node-role', {
        assumedBy: awsNodePrincipal
    })

    awsNodeRole.addManagedPolicy(iam.ManagedPolicy.fromAwsManagedPolicyName('AmazonEKS_CNI_Policy'))

    // Addons
    new eks.CfnAddon(this, 'vpc-cni', {
        addonName: 'vpc-cni',
        resolveConflicts: 'OVERWRITE',
        clusterName: cluster.clusterName,
        addonVersion: "v1.9.1-eksbuild.1",
        serviceAccountRoleArn: awsNodeRole.roleArn
    });
    new eks.CfnAddon(this, 'kube-proxy', {
        addonName: 'kube-proxy',
        resolveConflicts: 'OVERWRITE',
        clusterName: cluster.clusterName,
        addonVersion: "v1.21.2-eksbuild.2",
    });
    new eks.CfnAddon(this, 'core-dns', {
        addonName: 'coredns',
        resolveConflicts: 'OVERWRITE',
        clusterName: cluster.clusterName,
        addonVersion: "v1.8.4-eksbuild.1",
    });

    const awsAuth = new eks.AwsAuth(this, 'aws-auth', {cluster})
    awsAuth.addRoleMapping(mastersRole, {
        username: 'masterRole',
        groups: ['system:masters']
    });


    ///////////////////////////////////
    // install AWS load balancer via Helm charts
    const iamIngressPolicyDocument = JSON.parse(fs.readFileSync('files/iam/aws-lb-controller-v2.3.0-iam-policy.json').toString());
    const iamIngressPolicy = new iam.Policy(this, 'aws-load-balancer-controller-policy', {
        policyName: 'AWSLoadBalancerControllerIAMPolicy',
        document: iam.PolicyDocument.fromJson(iamIngressPolicyDocument),
    })

    const sa = cluster.addServiceAccount('aws-load-balancer-controller', {
        name: 'aws-load-balancer-controller',
        namespace: 'kube-system',
    });
    sa.role.attachInlinePolicy(iamIngressPolicy);

    const awsLoadBalancerControllerChart = cluster.addHelmChart('aws-loadbalancer-controller', {
      chart: 'aws-load-balancer-controller',
      repository: 'https://aws.github.io/eks-charts',
      namespace: 'kube-system',
      release: 'aws-load-balancer-controller',
      version: '1.3.2', // mapping to v2.3.0
      wait: true,
      timeout: cdk.Duration.minutes(15),
      values: {
        clusterName: cluster.clusterName,
        serviceAccount: {
          create: false,
          name: sa.serviceAccountName,
        },
        // must disable waf features for aws-cn partition
        enableShield: false,
        enableWaf: false,
        enableWafv2: false,
      },
    });
    awsLoadBalancerControllerChart.node.addDependency(nodeGroup);
    awsLoadBalancerControllerChart.node.addDependency(sa);
    awsLoadBalancerControllerChart.node.addDependency(cluster.openIdConnectProvider);
    awsLoadBalancerControllerChart.node.addDependency(cluster.awsAuth);

    ///////////////////////////////////
    // install EFS, EFS CSI driver via Helm charts
    const efsCSI = cluster.addHelmChart('EFSCSIDriver', {
        chart: 'aws-efs-csi-driver',
        repository: 'https://kubernetes-sigs.github.io/aws-efs-csi-driver/',
        release: 'aws-efs-csi-driver',
        version: '2.2.0',
    });
    efsCSI.node.addDependency(nodeGroup);
    efsCSI.node.addDependency(cluster.openIdConnectProvider);
    efsCSI.node.addDependency(cluster.awsAuth);

    ///////////////////////////////////
    // install game-2048
    const manifestGame = yaml.loadAll(fs.readFileSync('files/eks/game-2048.yaml', 'utf-8')) as Record<string, any>[];
    const manifestGameApply = new eks.KubernetesManifest(this, 'game-2048-deploy', {
        cluster,
        manifest: manifestGame,
        prune: false
    });
    manifestGameApply.node.addDependency(awsLoadBalancerControllerChart)

    const ecrRepository = new ecr.Repository(this, "image", {
        repositoryName: name + '-amazon-eks' 
    });
  
    /**
     * CodeCommit: create repository
     **/
    const codecommitRepository = new codecommit.Repository(this, "source", {
        repositoryName: name
    });
  
    const codebuildKubectlExecutionRole = new iam.Role(this, "codebuild-kubectl-role", {
        roleName: 'AmazonCodeBuildKubectlRole',
        assumedBy: new iam.ServicePrincipal("codebuild.amazonaws.com"),
        inlinePolicies: {
            AmazonECR: new iam.PolicyDocument({
                statements: [
                    new iam.PolicyStatement({
                        effect: iam.Effect.ALLOW,
                        actions: [
                            "logs:CreateLogGroup",
                            "logs:CreateLogStream",
                            "logs:PutLogEvents",
                            "codebuild:CreateReportGroup",
                            "codebuild:CreateReport",
                            "codebuild:UpdateReport",
                            "codebuild:BatchPutTestCases",
                            "codebuild:BatchPutCodeCoverages",
                            "ecr:BatchCheckLayerAvailability",
                            "ecr:GetDownloadUrlForLayer",
                            "ecr:BatchGetImage",
                            "ecr:GetAuthorizationToken",
                            "ecr:PutImage",
                            "ecr:InitiateLayerUpload",
                            "ecr:UploadLayerPart",
                            "ecr:CompleteLayerUpload",
                            "ecr:Describe*",
                            "s3:GetObject*",
                            "s3:GetBucket*",
                            "s3:List*",
                            "s3:DeleteObject*",
                            "s3:PutObject*",
                            "s3:Abort*",
                            "kms:Decrypt",
                            "kms:DescribeKey",
                            "kms:Encrypt",
                            "kms:ReEncrypt*",
                            "kms:GenerateDataKey*",
                            "kms:Decrypt",
                            "kms:Encrypt",
                            "kms:ReEncrypt*",
                            "kms:GenerateDataKey*"
                        ],
                        resources: ["*"],
                    }),
                ]
            })
        }
    })


    /**
     * CodeBuild:
     * 1. create codebuild project
     * 2. create policy of ECR and Codecommit
     **/
    const codebuildProject = new codebuild.PipelineProject(this, "build", {
        projectName: name,
        role: codebuildKubectlExecutionRole,
        buildSpec: codebuild.BuildSpec.fromObject(
            yaml.load(
                fs.readFileSync(
                    'files/codebuild/deploy-eks-game2048.yml',
                    'utf8'
                )
            ) as Record<string, any>[]
        ),
        environment: {
            computeType: codebuild.ComputeType.SMALL,
            buildImage: codebuild.LinuxBuildImage.AMAZON_LINUX_2_3,
            privileged: true,
            environmentVariables: {
                AWS_ACCOUNT_ID: {
                    type: codebuild.BuildEnvironmentVariableType.PLAINTEXT,
                    value: cdk.Aws.ACCOUNT_ID
                },
                IMAGE_URI: {
                    type: codebuild.BuildEnvironmentVariableType.PLAINTEXT,
                    value: ecrRepository.repositoryUri
                },
                EKS_CLUSTER_NAME: {
                    type: codebuild.BuildEnvironmentVariableType.PLAINTEXT,
                    value: name + '-eks-sample'
                }
            }
        }
    });
  
    codecommitRepository.onCommit('OnCommit', {
        target: new targets.CodeBuildProject(codebuildProject),
    });
    ecrRepository.grantPullPush(codebuildProject.role!);
  
    /**
     * CodePipeline:
     * 1. create codebuild project
     * 2. create policy of ECR and Codecommit
     **/

    // trigger of `CodeCommitTrigger.POLL`
    const sourceOutput = new codepipeline.Artifact();
    const sourceAction = new codepipeline_actions.CodeCommitSourceAction({
        actionName: "Source-CodeCommit",
        branch: 'main',
        trigger: codepipeline_actions.CodeCommitTrigger.POLL,
        repository: codecommitRepository,
        output: sourceOutput
    });

    // when codecommit input then action of codebuild
    const buildOutput = new codepipeline.Artifact();
    const buildAction = new codepipeline_actions.CodeBuildAction({
        actionName: "Build",
        input: sourceOutput,
        outputs: [
            buildOutput
        ],
        project: codebuildProject
    });
  
      // create pipeline, and then add both codecommit and codebuild
    const pipeline = new codepipeline.Pipeline(this, "pipeline", {
        pipelineName: name + '-pipeline'
    });
    pipeline.addStage({
        stageName: "Source",
        actions: [sourceAction]
    });
    pipeline.addStage({
        stageName: "Build",
        actions: [buildAction]
    });

    const rdb = new rds.DatabaseCluster(this, 'rds', {
        engine: rds.DatabaseClusterEngine.auroraMysql({ version: rds.AuroraMysqlEngineVersion.VER_2_08_1 }),
        instanceProps: {
          vpcSubnets: {
            subnetType: ec2.SubnetType.PRIVATE_WITH_NAT,
          },
          vpc,
        },
    });

    const elasticacheSecurityGroup = new ec2.SecurityGroup(this, 'elasticache-sg', {
        vpc,
        allowAllOutbound: true,
        securityGroupName: name + '-elasticache-sg'
    });
    elasticacheSecurityGroup.addIngressRule(
        ec2.Peer.anyIpv4(),
        ec2.Port.tcp(11511),
        'Allows Port 11511 access from Internet'
    )

    const elasticacheSubnetGroup = new elasticache.CfnSubnetGroup(this, 'subnet-group', {
        cacheSubnetGroupName: name + '-subnet',
        subnetIds: vpc.privateSubnets.map((subnet) => subnet.subnetId),
        description: `${id} redis subnet group`,
    });

    new elasticache.CfnCacheCluster(this, 'elasticache', {
        cacheNodeType: 'cache.t3.micro',
        engine: 'redis',
        numCacheNodes: 1,
        clusterName: name + '-memcached',
        vpcSecurityGroupIds: [elasticacheSecurityGroup.securityGroupId],
        cacheSubnetGroupName: elasticacheSubnetGroup.ref
    })

  }
}
