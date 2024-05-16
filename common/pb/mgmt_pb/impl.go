package mgmt_pb

func (request *InspectRequest) GetContentType() int32 {
	return int32(ContentType_InspectRequestType)
}

func (request *InspectResponse) GetContentType() int32 {
	return int32(ContentType_InspectResponseType)
}

func (request *MgmtPipeRequest) GetContentType() int32 {
	return int32(ContentType_MgmtPipeRequestType)
}

func (request *MgmtPipeResponse) GetContentType() int32 {
	return int32(ContentType_MgmtPipeResponseType)
}

func (request *RaftMemberListResponse) GetContentType() int32 {
	return int32(ContentType_RaftListMembersResponseType)
}

func (request *ValidateTerminatorsRequest) GetContentType() int32 {
	return int32(ContentType_ValidateTerminatorsRequestType)
}

func (request *ValidateTerminatorsResponse) GetContentType() int32 {
	return int32(ContentType_ValidateTerminatorResponseType)
}

func (request *TerminatorDetail) GetContentType() int32 {
	return int32(ContentType_ValidateTerminatorResultType)
}

func (request *ValidateRouterLinksRequest) GetContentType() int32 {
	return int32(ContentType_ValidateRouterLinksRequestType)
}

func (request *ValidateRouterLinksResponse) GetContentType() int32 {
	return int32(ContentType_ValidateRouterLinksResponseType)
}

func (request *RouterLinkDetails) GetContentType() int32 {
	return int32(ContentType_ValidateRouterLinksResultType)
}

func (request *ValidateRouterSdkTerminatorsRequest) GetContentType() int32 {
	return int32(ContentType_ValidateRouterSdkTerminatorsRequestType)
}

func (request *ValidateRouterSdkTerminatorsResponse) GetContentType() int32 {
	return int32(ContentType_ValidateRouterSdkTerminatorsResponseType)
}

func (request *RouterSdkTerminatorsDetails) GetContentType() int32 {
	return int32(ContentType_ValidateRouterSdkTerminatorsResultType)
}

func (x DestinationType) CheckControllers() bool {
	return x == DestinationType_Any || x == DestinationType_Controller
}

func (x DestinationType) CheckRouters() bool {
	return x == DestinationType_Any || x == DestinationType_Router
}
