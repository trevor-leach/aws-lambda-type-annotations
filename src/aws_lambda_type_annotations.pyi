import sys
if sys.version_info < (3, 8):
    from typing import (Any, Dict, List, Optional, Union)
    from typing_extensions import (Literal, Protocol, TypedDict)
else:
    from typing import (Any, Dict, List, Optional, Union,
                        Literal, Protocol, TypedDict)


AuthResponseContext = Dict[str, Any]


class APIGatewayEventRequestContextIdentity(TypedDict):
    accessKey: Optional[str]
    accountId: Optional[str]
    apiKey: Optional[str]
    apiKeyId: Optional[str]
    caller: Optional[str]
    cognitoAuthenticationProvider: Optional[str]
    cognitoAuthenticationType: Optional[str]
    cognitoIdentityId: Optional[str]
    cognitoIdentityPoolId: Optional[str]
    sourceIp: str
    user: Optional[str]
    userAgent: Optional[str]
    userArn: Optional[str]


class APIGatewayEventRequestContext(TypedDict, total=False):
    accountId: str
    apiId: str
    authorizer: Optional[AuthResponseContext]
    connectedAt: int
    connectionId: str
    domainName: str
    domainPrefix: str
    eventType: str
    extendedRequestId: str
    httpMethod: str
    identity: APIGatewayEventRequestContextIdentity
    messageDirection: str
    messageId: Optional[str]
    path: str
    stage: str
    requestId: str
    requestTime: str
    requestTimeEpoch: int
    resourceId: str
    resourcePath: str
    routeKey: str


class APIGatewayProxyEvent(TypedDict):
    body: Optional[str]
    headers: Dict[str, str]
    multiValueHeaders: Dict[str, List[str]]
    httpMethod: str
    isBase64Encoded: bool
    path: str
    pathParameters: Optional[Dict[str, str]]
    queryStringParameters: Optional[Dict[str, str]]
    multiValueQueryStringParameters: Optional[Dict[str, List[str]]]
    stageVariables: Optional[Dict[str, str]]
    requestContext: APIGatewayEventRequestContext
    resource: str


class ALBEventRequestContextElb(TypedDict):
    targetGroupArn: str


class ALBEventRequestContext(TypedDict):
    elb: ALBEventRequestContextElb


class ALBEvent(TypedDict, total=False):
    requestContext: ALBEventRequestContext
    httpMethod: str
    path: str
    queryStringParameters: Optional[Dict[str, str]]
    headers: Optional[Dict[str, str]]
    multiValueQueryStringParameters: Optional[Dict[str, List[str]]]
    multiValueHeaders: Optional[Dict[str, List[str]]]
    body: Optional[str]
    isBase64Encoded: bool


class CustomAuthorizerEvent(TypedDict, total=False):
    type: str
    methodArn: str
    authorizationToken: str
    resource: str
    path: str
    httpMethod: str
    headers: Dict[str, str]
    multiValueHeaders: Dict[str, List[str]]
    pathParameters: Optional[Dict[str, str]]
    queryStringParameters: Optional[Dict[str, str]]
    multiValueQueryStringParameters: Optional[Dict[str, List[str]]]
    stageVariables: Dict[str, str]
    requestContext: APIGatewayEventRequestContext
    domainName: str
    apiId: str


class AttributeValue(TypedDict, total=False):
    B: str
    BS: List[str]
    BOOL: bool
    L: List['AttributeValue']
    M: Dict[str, 'AttributeValue']
    N: str
    NS: List[str]
    NULL: bool
    S: str
    SS: List[str]


StreamRecordStreamViewType = Literal['KEYS_ONLY', 'NEW_IMAGE', 'OLD_IMAGE', 'NEW_AND_OLD_IMAGES']


class StreamRecord(TypedDict, total=False):
    ApproximateCreationDateTime: int
    Keys: Dict[str, AttributeValue]
    NewImage: Dict[str, AttributeValue]
    OldImage: Dict[str, AttributeValue]
    SequenceNumber: str
    SizeBytes: int
    StreamViewType: StreamRecordStreamViewType


DynamoDBRecordEventName = Literal['INSERT', 'MODIFY', 'REMOVE']


class DynamoDBRecord(TypedDict, total=False):
    awsRegion: str
    dynamodb: StreamRecord
    eventID: str
    eventName: DynamoDBRecordEventName
    eventSource: str
    eventSourceARN: str
    eventVersion: str
    userIdentity: Any


class DynamoDBStreamEvent(TypedDict):
    Records: List[DynamoDBRecord]


class SNSMessageAttribute(TypedDict):
    Type: str
    Value: str


SNSMessageAttributes = Dict[str, SNSMessageAttribute]


class SNSMessage(TypedDict):
    SignatureVersion: str
    Timestamp: str
    Signature: str
    SigningCertUrl: str
    MessageId: str
    Message: str
    MessageAttributes: SNSMessageAttributes
    Type: str
    UnsubscribeUrl: str
    TopicArn: str
    Subject: str


class SNSEventRecord(TypedDict):
    EventVersion: str
    EventSubscriptionArn: str
    EventSource: str
    Sns: SNSMessage


class SNSEvent(TypedDict):
    Records: List[SNSEventRecord]


class S3BucketOwnerIdentity(TypedDict):
    principalId: str


class S3Bucket(TypedDict):
    name: str
    ownerIdentity: S3BucketOwnerIdentity
    arn: str


class S3Object(TypedDict):
    key: str
    size: int
    eTag: str
    versionId: str
    sequencer: str


class S3EventRecordS3(TypedDict):
    s3SchemaVersion: str
    configurationId: str
    bucket: S3Bucket
    object: S3Object


S3EventRecordResponseElements = TypedDict('S3EventRecordResponseElements', {
    'x-amz-request-id': str,
    'x-amz-id-2': str
})


class S3EventRecordRequestParameters(TypedDict):
    sourceIPAddress: str


class S3EventRecordUserIdentity(TypedDict):
    principalId: str


class S3EventRecord(TypedDict):
    eventVersion: str
    eventSource: str
    awsRegion: str
    eventTime: str
    eventName: str
    userIdentity: S3EventRecordUserIdentity
    requestParameters: S3EventRecordRequestParameters
    responseElements: S3EventRecordResponseElements
    s3: S3EventRecordS3


class S3Event(TypedDict):
    Records: List[S3EventRecord]


class S3BatchEventJob(TypedDict):
    id: str


class S3BatchEventTask(TypedDict):
    taskId: str
    s3Key: str
    s3VersionId: Optional[str]
    S3BucketArn: str


class S3BatchEvent(TypedDict):
    invocationSchemaVersion: str
    invocationId: str
    job: S3BatchEventJob
    tasks: List[S3BatchEventTask]


S3BatchResultResultCode = Literal[
    'Succeeded',
    'TemporaryFailure',
    'PermanentFailure'
]


class S3BatchResultResult(TypedDict):
    taskId: str
    resultCode: S3BatchResultResultCode
    resultString: str


class S3BatchResult(TypedDict):
    invocationSchemaVersion: str
    treatMissingKeysAs: S3BatchResultResultCode
    invocationId: str
    results: List[S3BatchResultResult]


class CognitoUserPoolTriggerEventResponseClaimsOverrideDetailsGroupOverrideDetails(TypedDict, total=False):
    groupsToOverride: List[str]
    iamRolesToOverride: List[str]
    preferredRole: str


class CognitoUserPoolTriggerEventResponseClaimsOverrideDetails(TypedDict, total=False):
    claimsToAddOrOverride: Dict[str, str]
    claimsToSuppress: List[str]
    groupOverrideDetails: Optional[CognitoUserPoolTriggerEventResponseClaimsOverrideDetailsGroupOverrideDetails]


CognitoUserPoolTriggerEventResponseFinalUserStatus = Literal["CONFIRMED", "RESET_REQUIRED"]


CognitoUserPoolTriggerEventResponseMessageAction = Literal["SUPPRESS"]


CognitoUserPoolTriggerEventResponseDesiredDeliveryMediumsElement = Literal["EMAIL", "SMS"]


class CognitoUserPoolTriggerEventResponse(TypedDict, total=False):
    autoConfirmUser: bool
    autoVerifyPhone: bool
    autoVerifyEmail: bool
    smsMessage: str
    emailMessage: str
    emailSubject: str
    challengeName: str
    issueTokens: bool
    failAuthentication: bool
    publicChallengeParameters: Dict[str, str]
    privateChallengeParameters: Dict[str, str]
    challengeMetadata: str
    answerCorrect: bool
    userAttributes: Dict[str, str]
    finalUserStatus: CognitoUserPoolTriggerEventResponseFinalUserStatus
    messageAction: CognitoUserPoolTriggerEventResponseMessageAction
    desiredDeliveryMediums: List[CognitoUserPoolTriggerEventResponseDesiredDeliveryMediumsElement]
    forceAliasCreation: bool
    claimsOverrideDetails: CognitoUserPoolTriggerEventResponseClaimsOverrideDetails


CognitoUserPoolTriggerEventRequestSessionElementChallengeName = Literal[
    "CUSTOM_CHALLENGE",
    "PASSWORD_VERIFIER",
    "SMS_MFA",
    "DEVICE_SRP_AUTH",
    "DEVICE_PASSWORD_VERIFIER",
    "ADMIN_NO_SRP_AUTH"
]


class CognitoUserPoolTriggerEventRequestSessionElement(TypedDict, total=False):
    challengeName: CognitoUserPoolTriggerEventRequestSessionElementChallengeName
    challengeResult: bool
    challengeMetadata: str


class CognitoUserPoolTriggerEventRequest(TypedDict, total=False):
    userAttributes: Dict[str, str]
    validationData: Dict[str, str]
    codeParameter: str
    linkParameter: str
    usernameParameter: str
    newDeviceUsed: bool
    session: List[CognitoUserPoolTriggerEventRequestSessionElement]
    challengeName: str
    privateChallengeParameters: Dict[str, str]
    challengeAnswer: str
    password: str


class CognitoUserPoolTriggerEventCallerContext(TypedDict):
    awsSdkVersion: str
    clientId: str


CognitoUserPoolTriggerEventTriggerSource = Literal[
    "PreSignUp_SignUp",
    "PreSignUp_ExternalProvider",
    "PostConfirmation_ConfirmSignUp",
    "PreAuthentication_Authentication",
    "PostAuthentication_Authentication",
    "CustomMessage_SignUp",
    "CustomMessage_AdminCreateUser"
    "CustomMessage_ResendCode",
    "CustomMessage_ForgotPassword",
    "CustomMessage_UpdateUserAttribute",
    "CustomMessage_VerifyUserAttribute",
    "CustomMessage_Authentication",
    "DefineAuthChallenge_Authentication",
    "CreateAuthChallenge_Authentication",
    "VerifyAuthChallengeResponse_Authentication",
    "PreSignUp_AdminCreateUser",
    "PostConfirmation_ConfirmForgotPassword",
    "TokenGeneration_HostedAuth",
    "TokenGeneration_Authentication",
    "TokenGeneration_NewPasswordChallenge",
    "TokenGeneration_AuthenticateDevice",
    "TokenGeneration_RefreshTokens",
    "UserMigration_Authentication",
    "UserMigration_ForgotPassword"
]


class CognitoUserPoolTriggerEvent(TypedDict, total=False):
    version: int
    triggerSource: CognitoUserPoolTriggerEventTriggerSource
    region: str
    userPoolId: str
    userName: str
    callerContext: CognitoUserPoolTriggerEventCallerContext
    request: CognitoUserPoolTriggerEventRequest
    response: CognitoUserPoolTriggerEventResponse


class CloudFormationCustomResourceEventCommon(TypedDict):
    ServiceToken: str
    ResponseURL: str
    StackId: str
    RequestId: str
    LogicalResourceId: str
    ResourceType: str
    ResourceProperties: Dict[str, Any]  # ServiceToken: str, and any other string keyed values


CloudFormationCustomResourceCreateEventRequestType = Literal['Create']


CloudFormationCustomResourceUpdateEventRequestType = Literal['Update']


CloudFormationCustomResourceDeleteEventRequestType = Literal['Delete']


class CloudFormationCustomResourceCreateEvent(CloudFormationCustomResourceEventCommon):
    RequestType: CloudFormationCustomResourceCreateEventRequestType


class CloudFormationCustomResourceUpdateEvent(CloudFormationCustomResourceEventCommon):
    RequestType: CloudFormationCustomResourceUpdateEventRequestType
    PhysicalResourceId: str
    OldResourceProperties: Dict[str, Any]


class CloudFormationCustomResourceDeleteEvent(CloudFormationCustomResourceEventCommon):
    RequestType: CloudFormationCustomResourceDeleteEventRequestType
    PhysicalResourceId: str


CloudFormationCustomResourceEvent = Union[
    CloudFormationCustomResourceCreateEvent,
    CloudFormationCustomResourceUpdateEvent,
    CloudFormationCustomResourceDeleteEvent
]


class CloudFormationCustomResourceResponseCommon(TypedDict, total=False):
    PhysicalResourceId: str
    StackId: str
    RequestId: str
    LogicalResourceId: str
    Data: Dict[str, Any]
    NoEcho: bool


CloudFormationCustomResourceSuccessResponseStatus = Literal["SUCCESS"]


CloudFormationCustomResourceFailedResponseStatus = Literal["FAILED"]


class CloudFormationCustomResourceSuccessResponse(CloudFormationCustomResourceResponseCommon, total=False):
    Status: CloudFormationCustomResourceSuccessResponseStatus
    Reason: str


class CloudFormationCustomResourceFailedResponse(CloudFormationCustomResourceResponseCommon, total=False):
    Status: CloudFormationCustomResourceFailedResponseStatus
    Reason: str


CloudFormationCustomResourceResponse = Union[
    CloudFormationCustomResourceSuccessResponse,
    CloudFormationCustomResourceFailedResponse
]

ScheduledEvent = TypedDict('ScheduledEvent', {
    'account': str,
    'region': str,
    'detail': Any,
    'detail-type': str,
    'source': str,
    'time': str,
    'id': str,
    'resources': List[str]
})


class CloudWatchLogsEventData(TypedDict):
    data: str


class CloudWatchLogsEvent(TypedDict):
    awslogs: CloudWatchLogsEventData


class CloudWatchLogsLogEvent(TypedDict, total=False):
    id: str
    timestamp: int
    message: str
    extractedFields: Dict[str, str]


class CloudWatchLogsDecodedData(TypedDict):
    owner: str
    logGroup: str
    logStream: str
    subscriptionFilters: List[str]
    messageType: str
    logEvents: List[CloudWatchLogsLogEvent]


class CognitoIdentity(Protocol):
    cognitoIdentityId: str
    cognitoIdentityPoolId: str


class ClientContextClient(Protocol):
    installationId: str
    appTitle: str
    appVersionName: str
    appVersionCode: str
    appPackageName: str


class ClientContextEnv(Protocol):
    platformVersion: str
    platform: str
    make: str
    model: str
    locale: str


class ClientContext(Protocol):
    client: ClientContextClient
    Custom: Any
    env: ClientContextEnv


class ContextBase(Protocol):
    function_name: str
    function_version: str
    invoked_function_arn: str
    memory_limit_in_mb: int
    aws_request_id: str
    log_group_name: str
    log_stream_name: str
    def get_remaining_time_in_millis(self) -> int: ...


class MobileAppContext(ContextBase):
    identity: CognitoIdentity
    client_context: ClientContext


Context = Union[ContextBase, MobileAppContext]


class APIGatewayProxyResult(TypedDict, total=False):
    statusCode: int
    headers: Dict[str, Union[str, bool, int]]
    multiValueHeaders: Dict[str, List[Union[str, bool, int]]]
    body: str
    isBase64Encoded: bool


class ALBResult(TypedDict, total=False):
    statusCode: int
    statusDescription: str
    headers: Dict[str, Union[str, bool, int]]
    multiValueHeaders: Dict[str, List[Union[str, bool, int]]]
    body: str
    isBase64Encoded: bool


Condition = Dict[str, Union[str, List[str]]]

ConditionBlock = Dict[str, Union[Condition, List[Condition]]]


class BaseStatement(TypedDict, total=False):
    Effect: str
    Sid: str
    Condition: ConditionBlock


PrincipalValue = Union[
    Dict[str, Union[str, List[str]]],
    str,
    List[str]
]
class StatementPrincipalPositive(TypedDict):
    Principal: PrincipalValue
class StatementPrincipalNegative(TypedDict):
    NotPrincipal: PrincipalValue
class MaybeStatementPrincipal(TypedDict, total=False):
    Principal: PrincipalValue
    NotPrincipal: PrincipalValue
class MaybeStatementResource(TypedDict, total=False):
    Resource: Union[str, List[str]]
    NotResource: Union[str, List[str]]
class StatementResourcePositive(TypedDict):
    Resource: Union[str, List[str]]
class StatementResourceNegative(TypedDict):
    NotResource: Union[str, List[str]]
class StatementActionPositive(TypedDict):
    Action: Union[str, List[str]]
class StatementActionNegative(TypedDict):
    NotAction: Union[str, List[str]]


# StatementAction = Union[StatementActionPositive, StatementActionNegative]
class MaybeStatementAction(TypedDict, total=False):
    Action: Union[str, List[str]]
    NotAction: Union[str, List[str]]


# class StatementResource(MaybeStatementPrincipal, Union[StatementResourcePositive, StatementResourceNegative]):
#     pass


# class StatementPrincipal(MaybeStatementResource, Union[StatementPrincipalPositive, StatementPrincipalNegative]):
#     pass


# class Statement(BaseStatement, StatementAction, Union[StatementResource, StatementPrincipal]):
#     pass

class StatementResource(MaybeStatementPrincipal, MaybeStatementResource, total=False):
    pass


class StatementPrincipal(MaybeStatementResource, MaybeStatementPrincipal, total=False):
    pass


class Statement(BaseStatement, MaybeStatementAction, MaybeStatementResource, MaybeStatementPrincipal, total=False):
    pass


class PolicyDocument(TypedDict, total=False):
    Version: str
    Id: str
    Statement: List[Statement]


class CustomAuthorizerResult(TypedDict, total=False):
    principalId: str
    policyDocument: PolicyDocument
    context: AuthResponseContext
    usageIdentifierKey: str


class S3ArtifactLocation(TypedDict):
    bucketName: str
    objectKey: str


S3ArtifactStoreType = Literal['S3']


class S3ArtifactStore(TypedDict):
    type: S3ArtifactStoreType
    s3Location: S3ArtifactLocation


class Artifact(TypedDict):
    name: str
    revision: Optional[str]
    location: S3ArtifactStore


class Credentials(TypedDict, total=False):
    accessKeyId: str
    secretAccessKey: str
    sessionToken: str


class EncryptionKey(TypedDict):
    type: str
    id: str


CodePipelineEventDataEncryptionKeyType = Literal['KMS']


class CodePipelineEventDataEncryptionKey(TypedDict):
    type: CodePipelineEventDataEncryptionKeyType
    id: str


class CodePipelineEventActionConfigurationConfiguration(TypedDict):
    FunctionName: str
    UserParameters: str


class CodePipelineEventActionConfiguration(TypedDict):
    configuuration: CodePipelineEventActionConfigurationConfiguration


class CodePipelineEventData(TypedDict, total=False):
    actionConfiguration: CodePipelineEventActionConfiguration
    inputArtifacts: List[Artifact]
    outputArtifacts: List[Artifact]
    artifactCredentials: Credentials
    encryptionKey: CodePipelineEventDataEncryptionKey
    continuationToken: str


class CodePipelineEventCodePipelineJob(TypedDict):
    id: str
    accountId: str
    data: CodePipelineEventData


CodePipelineEvent = TypedDict('CodePipelineEvent', {
    'CodePipeline.job': CodePipelineEventCodePipelineJob
})


CodePipelineState = Literal[
    'STARTED',
    'SUCCEEDED',
    'RESUMED',
    'FAILED',
    'CANCELED',
    'SUPERSEDED'
]


CodePipelineStageState = Literal[
    'STARTED',
    'SUCCEEDED',
    'RESUMED',
    'FAILED',
    'CANCELED'
]


CodePipelineActionState = Literal[
    'STARTED',
    'SUCCEEDED',
    'FAILED',
    'CANCELED'
]


CodePipelineCloudWatchPipelineEventDetail = TypedDict('CodePipelineCloudWatchPipelineEventDetail', {
    'pipeline': str,
    'version': int,
    'state': CodePipelineState,
    'execution-id': str
})


CodePipelineCloudWatchPipelineEvent = TypedDict('CodePipelineCloudWatchPipelineEvent', {
    'version': str,
    'id': str,
    'detail-type': Literal['CodePipeline Pipeline Execution State Change'],
    'source': Literal['aws.codepipeline'],
    'account': str,
    'time': str,
    'region': str,
    'resources': List[str],
    'detail': CodePipelineCloudWatchPipelineEventDetail
})


CodePipelineCloudWatchStageEventDetail = TypedDict('CodePipelineCloudWatchStageEventDetail', {
    'pipeline': str,
    'version': int,
    'execution-id': str,
    'stage': str,
    'state': CodePipelineState
})


CodePipelineCloudWatchStageEvent = TypedDict('CodePipelineCloudWatchStageEvent', {
    'version': str,
    'id': str,
    'detail-type': Literal['CodePipeline Stage Execution State Change'],
    'source': Literal['aws.codepipeline'],
    'account': str,
    'time': str,
    'region': str,
    'resources': List[str],
    'detail': CodePipelineCloudWatchStageEventDetail
})


CodePipelineActionCategory = Literal[
    'Approval',
    'Build',
    'Deploy',
    'Invoke',
    'Source',
    'Test'
]


CodePipelineCloudWatchActionEventDetailTypeOwner = Literal['AWS', 'Custom', 'ThirdParty']


class CodePipelineCloudWatchActionEventDetailType(TypedDict):
    owner: CodePipelineCloudWatchActionEventDetailTypeOwner
    category: CodePipelineActionCategory
    provider: str
    version: int


CodePipelineCloudWatchActionEventDetail = TypedDict('CodePipelineCloudWatchActionEventDetail', {
    'pipeline': str,
    'version': int,
    'execution-id': str,
    'stage': str,
    'action': str,
    'state': CodePipelineActionState,
    'type': CodePipelineCloudWatchActionEventDetailType
})


CodePipelineCloudWatchActionEvent = TypedDict('CodePipelineCloudWatchActionEvent', {
    'version': str,
    'id': str,
    'detail-type': Literal['CodePipeline Action Execution State Change'],
    'source': Literal['aws.codepipeline'],
    'account': str,
    'time': str,
    'region': str,
    'resources': List[str],
    'detail': CodePipelineCloudWatchActionEventDetail
})


CodePipelineCloudWatchEvent = Union[
    CodePipelineCloudWatchPipelineEvent,
    CodePipelineCloudWatchStageEvent,
    CodePipelineCloudWatchActionEvent
]


class CloudFrontHeadersValueElement(TypedDict, total=False):
    key: str
    value: str


CloudFrontHeaders = Dict[str, List[CloudFrontHeadersValueElement]]


CloudFrontCustomOriginProtocol = Literal['http', 'https']


class CloudFrontCustomOrigin(TypedDict):
    customHeaders: CloudFrontHeaders
    domainName: str
    keepaliveTimeout: int
    path: str
    port: int
    protocol: CloudFrontCustomOriginProtocol
    readTimeout: int
    sslProtocols: List[str]


class CloudFrontOriginCustom(TypedDict, total=False):
    custom: CloudFrontCustomOrigin
    s3: None


CloudFrontS3OriginAuthMethod = Literal['origin-access-identity', 'none']


class CloudFrontS3Origin(TypedDict):
    authMethod: CloudFrontS3OriginAuthMethod
    customHeaders: CloudFrontHeaders
    domainName: str
    path: str
    region: str


class CloudFrontOriginS3(TypedDict, total=False):
    custom: None
    s3: CloudFrontS3Origin


CloudFrontOrigin = Union[CloudFrontS3Origin, CloudFrontCustomOrigin]


class CloudFrontResponse(TypedDict):
    status: str
    statusDescription: str
    headers: CloudFrontHeaders


class CloudFrontRequest(TypedDict, total=False):
    clientIp: str
    method: str
    uri: str
    querystring: str
    headers: CloudFrontHeaders
    origin: CloudFrontOrigin


CloudFrontEventConfigEventType = Literal['origin-request', 'origin-response', 'viewer-request', 'viewer-response']


class CloudFrontEventConfig(TypedDict):
    distributionDomainName: str
    distributionId: str
    eventType: CloudFrontEventConfigEventType
    requestId: str


class CloudFrontEvent(TypedDict):
    config: CloudFrontEventConfig


CloudFrontResultResponseBodyEncoding = Literal['text', 'base64']


class CloudFrontResultResponse(TypedDict, total=False):
    status: str
    statusDescription: str
    headers: CloudFrontHeaders
    bodyEncoding: CloudFrontResultResponseBodyEncoding
    body: str


class CloudFrontResponseEventRecordsElementCf(CloudFrontEvent):
    request: CloudFrontRequest
    response: CloudFrontResponse


class CloudFrontResponseEventRecordsElement(TypedDict):
    cf: CloudFrontResponseEventRecordsElementCf


class CloudFrontResponseEvent(TypedDict):
    Records: List[CloudFrontResponseEventRecordsElement]


CloudFrontRequestResult = Optional[Union[CloudFrontResultResponse, CloudFrontRequest]]


class CloudFrontRequestEventRecordsElementCf(CloudFrontEvent):
    request: CloudFrontRequest


class CloudFrontRequestEventRecordsElement(TypedDict):
    cf: CloudFrontRequestEventRecordsElementCf


class CloudFrontRequestEvent(TypedDict):
    Records: List[CloudFrontRequestEventRecordsElement]


CloudFrontResponseResult = Optional[CloudFrontResultResponse]


class KinesisStreamRecordPayload(TypedDict):
    approximateArrivalTimestamp: int
    data: str
    kinesisSchemaVersion: str
    partitionKey: str
    sequenceNumber: str


class KinesisStreamRecord(TypedDict):
    awsRegion: str
    eventID: str
    eventName: str
    eventSource: str
    eventSourceARN: str
    eventVersion: str
    invokeIdentityArn: str
    kinesis: KinesisStreamRecordPayload


class KinesisStreamEvent(TypedDict):
    Records: List[KinesisStreamRecord]


class FirehoseRecordMetadata(TypedDict):
    shardId: str
    partitionKey: str
    approximateArrivalTimestamp: str
    sequenceNumber: str
    subsequenceNumber: str


class FirehoseTransformationEventRecord(TypedDict, total=False):
    recordId: str
    approximateArrivalTimestamp: int
    data: str
    kinesisRecordMetadata: FirehoseRecordMetadata


class FirehoseTransformationEvent(TypedDict):
    invocationId: str
    deliveryStreamArn: str
    region: str
    records: List[FirehoseTransformationEventRecord]


FirehoseRecordTransformationStatus = Literal[
    'Ok', 'Dropped', 'ProcessingFailed'
]


class FirehoseTransformationResultRecord(TypedDict):
    recordId: str
    result: FirehoseRecordTransformationStatus
    data: str


class FirehoseTransformationResult(TypedDict):
    Records: List[FirehoseTransformationResultRecord]


class SQSRecordAttributes(TypedDict):
    ApproximateReceiveCount: str
    SentTimestamp: str
    SenderId: str
    ApproximateFirstReceiveTimestamp: str


class SQSMessageAttribute(TypedDict, toal=False):
    stringValue: str
    binaryValue: str
    stringListValues: List[None]  # Not implemented. Reserved for future use.
    binaryListValues: List[None]  # Not implemented. Reserved for future use.
    dataType: str  # 'String' | 'Number' | 'Binary' | str


SQSMessageAttributes = Dict[str, SQSMessageAttribute]


class SQSRecord(TypedDict):
    messageId: str
    receiptHandle: str
    body: str
    attributes: SQSRecordAttributes
    messageAttributes: SQSMessageAttributes
    md5OfBody: str
    eventSource: str
    eventSourceARN: str
    awsRegion: str


class SQSEvent(TypedDict):
    Records: List[SQSRecord]


class LexSlotResolution(TypedDict):
    value: str


class LexSlotDetailsValue(TypedDict):
    resolutions: List[LexSlotResolution]
    originalValue: str


LexEventCurrentIntentConfirmationStatus = Literal['None', 'Confirmed', 'Denied']


class LexEventCurrentIntent(TypedDict):
    name: str
    slots: Dict[str, Optional[str]]
    slotDetails: Dict[str, LexSlotDetailsValue]
    confirmationStatus: LexEventCurrentIntentConfirmationStatus


class LexEventBot(TypedDict):
    name: str
    alias: str
    version: str


LexEventInvocationSource = Literal['DialogCodeHook', 'FulfillmentCodeHook']


LexEventOutputDialogMode = Literal['Text', 'Voice']


LexEventMessageVersion = Literal['1.0']


class LexEvent(TypedDict):
    currentIntent: LexEventCurrentIntent
    bot: LexEventBot
    userId: str
    inputTranscript: str
    invocationSource: LexEventInvocationSource
    outputDialogMode: LexEventOutputDialogMode
    messageVersion: LexEventMessageVersion
    sessionAttributes: Dict[str, str]
    requestAttributes: Optional[Dict[str, str]]


class LexGenericAttachmentButtonsElement(TypedDict):
    text: str
    value: str


class LexGenericAttachment(TypedDict):
    title: str
    subTitle: str
    imageUrl: str
    attachmentLinkUrl: str
    buttons: List[LexGenericAttachmentButtonsElement]


LexDialogActionBaseMessageContentType = Literal['PlainText', 'SSML', 'CustomPayload']


class LexDialogActionBaseMessage(TypedDict):
    contentType: LexDialogActionBaseMessageContentType
    content: str


LexDialogActionBaseResponseCardContentType = Literal['application/vnd.amazonaws.card.generic']


class LexDialogActionBaseResponseCard(TypedDict):
    version: int
    contentType: LexDialogActionBaseResponseCardContentType
    genericAttachments: List[LexGenericAttachment]


class LexDialogActionBase(TypedDict, total=False):
    # type: Literal['Close', 'ElicitIntent', 'ElicitSlot', 'ConfirmIntent']
    message: LexDialogActionBaseMessage
    responseCard: LexDialogActionBaseResponseCard


LexDialogActionCloseType = Literal['Close']


LexDialogActionCloseFulfillmentState = Literal['Fulfilled', 'Failed']


class LexDialogActionClose(LexDialogActionBase):
    type: LexDialogActionCloseType
    fulfillmentState: LexDialogActionCloseFulfillmentState


LexDialogActionElicitIntentType = Literal['ElicitIntent']


class LexDialogActionElicitIntent(LexDialogActionBase):
    type: LexDialogActionElicitIntentType


LexDialogActionElicitSlotType = Literal['ElicitSlot']


class LexDialogActionElicitSlot(LexDialogActionBase):
    type: LexDialogActionElicitSlotType
    intentName: str
    slots: Dict[str, Optional[str]]
    slotToElicit: str


LexDialogActionConfirmIntentType = Literal['ConfirmIntent']


class LexDialogActionConfirmIntent(LexDialogActionBase):
    type: LexDialogActionConfirmIntentType
    intentName: str
    slots: Dict[str, Optional[str]]


LexDialogActionDelegateType = Literal['Delegate']


class LexDialogActionDelegate(TypedDict):
    type: LexDialogActionDelegateType
    slots: Dict[str, Optional[str]]


LexDialogAction = Union[
    LexDialogActionClose,
    LexDialogActionElicitIntent,
    LexDialogActionElicitSlot,
    LexDialogActionConfirmIntent,
    LexDialogActionDelegate
]


class LexResult(TypedDict, total=False):
    sessionAttributes: Dict[str, str]
    dialogAction: LexDialogAction



def handle_dynamodb_stream_event(event: DynamoDBStreamEvent, context: Context) -> None: ...

def handle_sns_event(event: SNSEvent, context: Context) -> None: ...

def handle_congnito_user_pool_trigger_event(event: CognitoUserPoolTriggerEvent, context: Context) -> Any: ...

def handle_sqs_event(event: SQSEvent, context: Context) -> None: ...

def handle_cloudformation_custom_resource_event(event: CloudFormationCustomResourceEvent, context: Context) -> None: ...

def handle_cloudwatch_logs_event(event: CloudWatchLogsEvent, context: Context) -> None: ...

def handle_scheduled_event(event: ScheduledEvent, context: Context) -> None: ...

def handle_lex_event(event: LexEvent, context: Context) -> LexResult: ...

def handle_api_gateway_proxy_event(event: APIGatewayProxyEvent, context: Context) -> APIGatewayProxyResult: ...

def handle_alb_event(event: ALBEvent, context: Context) -> ALBResult: ...

def handle_codepipeline_event(event: CodePipelineEvent, context: Context) -> None: ...
def handle_codepipeline_cloudwatch_event(event: CodePipelineCloudWatchEvent, context: Context) -> None: ...
def handle_codepipeline_cloudwatch_pipeline_event(event: CodePipelineCloudWatchPipelineEvent, context: Context) -> None: ...
def handle_codepipeline_cloudwatch_stage_event(event: CodePipelineCloudWatchStageEvent, context: Context) -> None: ...
def handle_codepipeline_cloudwatch_action_event(event: CodePipelineCloudWatchActionEvent, context: Context) -> None: ...

def handle_cloudfront_request_event(event: CloudFrontRequestEvent, context: Context) -> CloudFrontRequestResult: ...
def handle_cloudfront_response_event(event: CloudFrontResponseEvent, context: Context) -> CloudFrontResponseResult: ...

def handle_kinesis_stream_event(event: KinesisStreamEvent, context: Context) -> None: ...
def handle_firehose_transformation_event(event: FirehoseTransformationEvent,context: Context) -> FirehoseTransformationResult: ...

def handle_custom_authorizer_event(event: CustomAuthorizerEvent,context: Context) -> CustomAuthorizerResult: ...

def handle_s3_event(event: S3Event, context: Context) -> None: ...
def handle_s3_batch_event(event: S3BatchEvent, context: Context) -> S3BatchResult: ...
