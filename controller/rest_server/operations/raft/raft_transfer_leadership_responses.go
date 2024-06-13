// Code generated by go-swagger; DO NOT EDIT.

//
// Copyright NetFoundry Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// __          __              _
// \ \        / /             (_)
//  \ \  /\  / /_ _ _ __ _ __  _ _ __   __ _
//   \ \/  \/ / _` | '__| '_ \| | '_ \ / _` |
//    \  /\  / (_| | |  | | | | | | | | (_| | : This file is generated, do not edit it.
//     \/  \/ \__,_|_|  |_| |_|_|_| |_|\__, |
//                                      __/ |
//                                     |___/

package raft

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/runtime"

	"github.com/openziti/ziti/controller/rest_model"
)

// RaftTransferLeadershipOKCode is the HTTP code returned for type RaftTransferLeadershipOK
const RaftTransferLeadershipOKCode int = 200

/*RaftTransferLeadershipOK Base empty response

swagger:response raftTransferLeadershipOK
*/
type RaftTransferLeadershipOK struct {

	/*
	  In: Body
	*/
	Payload *rest_model.Empty `json:"body,omitempty"`
}

// NewRaftTransferLeadershipOK creates RaftTransferLeadershipOK with default headers values
func NewRaftTransferLeadershipOK() *RaftTransferLeadershipOK {

	return &RaftTransferLeadershipOK{}
}

// WithPayload adds the payload to the raft transfer leadership o k response
func (o *RaftTransferLeadershipOK) WithPayload(payload *rest_model.Empty) *RaftTransferLeadershipOK {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the raft transfer leadership o k response
func (o *RaftTransferLeadershipOK) SetPayload(payload *rest_model.Empty) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *RaftTransferLeadershipOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(200)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// RaftTransferLeadershipUnauthorizedCode is the HTTP code returned for type RaftTransferLeadershipUnauthorized
const RaftTransferLeadershipUnauthorizedCode int = 401

/*RaftTransferLeadershipUnauthorized The currently supplied session does not have the correct access rights to request this resource

swagger:response raftTransferLeadershipUnauthorized
*/
type RaftTransferLeadershipUnauthorized struct {

	/*
	  In: Body
	*/
	Payload *rest_model.APIErrorEnvelope `json:"body,omitempty"`
}

// NewRaftTransferLeadershipUnauthorized creates RaftTransferLeadershipUnauthorized with default headers values
func NewRaftTransferLeadershipUnauthorized() *RaftTransferLeadershipUnauthorized {

	return &RaftTransferLeadershipUnauthorized{}
}

// WithPayload adds the payload to the raft transfer leadership unauthorized response
func (o *RaftTransferLeadershipUnauthorized) WithPayload(payload *rest_model.APIErrorEnvelope) *RaftTransferLeadershipUnauthorized {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the raft transfer leadership unauthorized response
func (o *RaftTransferLeadershipUnauthorized) SetPayload(payload *rest_model.APIErrorEnvelope) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *RaftTransferLeadershipUnauthorized) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(401)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// RaftTransferLeadershipNotFoundCode is the HTTP code returned for type RaftTransferLeadershipNotFound
const RaftTransferLeadershipNotFoundCode int = 404

/*RaftTransferLeadershipNotFound The requested resource does not exist

swagger:response raftTransferLeadershipNotFound
*/
type RaftTransferLeadershipNotFound struct {

	/*
	  In: Body
	*/
	Payload *rest_model.APIErrorEnvelope `json:"body,omitempty"`
}

// NewRaftTransferLeadershipNotFound creates RaftTransferLeadershipNotFound with default headers values
func NewRaftTransferLeadershipNotFound() *RaftTransferLeadershipNotFound {

	return &RaftTransferLeadershipNotFound{}
}

// WithPayload adds the payload to the raft transfer leadership not found response
func (o *RaftTransferLeadershipNotFound) WithPayload(payload *rest_model.APIErrorEnvelope) *RaftTransferLeadershipNotFound {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the raft transfer leadership not found response
func (o *RaftTransferLeadershipNotFound) SetPayload(payload *rest_model.APIErrorEnvelope) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *RaftTransferLeadershipNotFound) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(404)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// RaftTransferLeadershipTooManyRequestsCode is the HTTP code returned for type RaftTransferLeadershipTooManyRequests
const RaftTransferLeadershipTooManyRequestsCode int = 429

/*RaftTransferLeadershipTooManyRequests The resource requested is rate limited and the rate limit has been exceeded

swagger:response raftTransferLeadershipTooManyRequests
*/
type RaftTransferLeadershipTooManyRequests struct {

	/*
	  In: Body
	*/
	Payload *rest_model.APIErrorEnvelope `json:"body,omitempty"`
}

// NewRaftTransferLeadershipTooManyRequests creates RaftTransferLeadershipTooManyRequests with default headers values
func NewRaftTransferLeadershipTooManyRequests() *RaftTransferLeadershipTooManyRequests {

	return &RaftTransferLeadershipTooManyRequests{}
}

// WithPayload adds the payload to the raft transfer leadership too many requests response
func (o *RaftTransferLeadershipTooManyRequests) WithPayload(payload *rest_model.APIErrorEnvelope) *RaftTransferLeadershipTooManyRequests {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the raft transfer leadership too many requests response
func (o *RaftTransferLeadershipTooManyRequests) SetPayload(payload *rest_model.APIErrorEnvelope) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *RaftTransferLeadershipTooManyRequests) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(429)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// RaftTransferLeadershipInternalServerErrorCode is the HTTP code returned for type RaftTransferLeadershipInternalServerError
const RaftTransferLeadershipInternalServerErrorCode int = 500

/*RaftTransferLeadershipInternalServerError The supplied request contains invalid fields or could not be parsed (json and non-json bodies). The error's code, message, and cause fields can be inspected for further information

swagger:response raftTransferLeadershipInternalServerError
*/
type RaftTransferLeadershipInternalServerError struct {

	/*
	  In: Body
	*/
	Payload *rest_model.APIErrorEnvelope `json:"body,omitempty"`
}

// NewRaftTransferLeadershipInternalServerError creates RaftTransferLeadershipInternalServerError with default headers values
func NewRaftTransferLeadershipInternalServerError() *RaftTransferLeadershipInternalServerError {

	return &RaftTransferLeadershipInternalServerError{}
}

// WithPayload adds the payload to the raft transfer leadership internal server error response
func (o *RaftTransferLeadershipInternalServerError) WithPayload(payload *rest_model.APIErrorEnvelope) *RaftTransferLeadershipInternalServerError {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the raft transfer leadership internal server error response
func (o *RaftTransferLeadershipInternalServerError) SetPayload(payload *rest_model.APIErrorEnvelope) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *RaftTransferLeadershipInternalServerError) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(500)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}