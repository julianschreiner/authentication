package handlers

import (
	"context"

	pb "authentication"
)

// NewService returns a naive, stateless implementation of Service.
func NewService() pb.AuthenticationServer {
	return authenticationService{}
}

type authenticationService struct{}

func (s authenticationService) SignIn(ctx context.Context, in *pb.SignInRequest) (*pb.SignInResponse, error) {
	var resp pb.SignInResponse
	return &resp, nil
}

func (s authenticationService) SignOut(ctx context.Context, in *pb.SignOutRequest) (*pb.SignOutResponse, error) {
	var resp pb.SignOutResponse
	return &resp, nil
}

func (s authenticationService) Refresh(ctx context.Context, in *pb.RefreshRequest) (*pb.RefreshResponse, error) {
	var resp pb.RefreshResponse
	return &resp, nil
}
