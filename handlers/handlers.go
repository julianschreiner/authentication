package handlers

import (
	pb "authentication"
	"authentication/auth"
	"authentication/security"
	"authentication/user"
	"context"
	"fmt"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	logger "gorm.io/gorm/logger"
	"log"
	"os"
	"time"
)

const SuperGroupID = 4

var logger2 log.Logger

type authenticationService struct {
	authService  auth.AuthService
	superGroupId uint
}

// NewService returns a naive, stateless implementation of Service.
func NewService() pb.AuthenticationServer {
	log.Println("started auth-uas-svc")

	jwtPrivate := os.Getenv("JWT_PRIVATE")
	refreshSecret := os.Getenv("JWT_REFRESH")

	authJwt, err := security.NewJwtSigner(jwtPrivate, refreshSecret)
	if err != nil {
		println("failed to create jwt signer", "error", err)
		os.Exit(6)
	}

	/*
		Database
	*/
	dbHost := os.Getenv("DB_HOST")
	dbUserName := os.Getenv("DB_USER")
	dbSecret := os.Getenv("DB_SECRET")
	dbName := os.Getenv("DB_NAME")

	ioWriter := log.New(os.Stdout, "\r\n", log.LstdFlags)

	db, err := gorm.Open(mysql.Open(fmt.Sprintf("%s:%s@tcp(%s:3306)/%s?charset=utf8mb4&parseTime=True&loc=UTC", dbUserName, dbSecret, dbHost, dbName)), &gorm.Config{
		Logger: logger.New(ioWriter,
			logger.Config{
				SlowThreshold: time.Millisecond * 200,
				LogLevel:      0,
			},
		),
	})
	if err != nil {
		println("database is not reachable", "error", err)
		os.Exit(3)
	}

	err = db.AutoMigrate(&auth.Auth{}, &auth.Locker{})
	if err != nil {
		println("failed to migrate db", "error", err)
		os.Exit(7)
	}

	/* DOMAIN LOGIC */
	superID := uint(SuperGroupID)
	authRepository := auth.NewAuthRepository(db)

	userClient := user.NewUserClient()
	authSrv := auth.NewAuthService(authJwt, authRepository, &superID, &logger2, userClient)

	return authenticationService{
		authService:  authSrv,
		superGroupId: uint(SuperGroupID),
	}
}

func (s authenticationService) Register(ctx context.Context, in *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	cred, err := s.authService.Register(ctx, in.Email, in.Password, in.Forename, in.Surname, in.Dob)
	if err != nil {
		return nil, err
	}

	return &pb.RegisterResponse{
		Access:  cred.AccessToken,
		Refresh: cred.RefreshToken,
	}, nil
}

func (s authenticationService) SignIn(ctx context.Context, in *pb.SignInRequest) (*pb.SignInResponse, error) {
	cred, err := s.authService.SignIn(ctx, in.Email, in.Password)
	if err != nil {
		return nil, err
	}

	return &pb.SignInResponse{
		Access:  cred.AccessToken,
		Refresh: cred.RefreshToken,
	}, nil
}

func (s authenticationService) SignOut(ctx context.Context, in *pb.SignOutRequest) (*pb.SignOutResponse, error) {
	err := s.authService.SignOut(ctx, in.Refresh)
	if err != nil {
		return nil, err
	}
	return &pb.SignOutResponse{}, nil
}

func (s authenticationService) Refresh(ctx context.Context, in *pb.RefreshRequest) (*pb.RefreshResponse, error) {
	cred, err := s.authService.Refresh(ctx, in.Refresh)
	if err != nil {
		return nil, err
	}

	return &pb.RefreshResponse{
		Access:  cred.AccessToken,
		Refresh: cred.RefreshToken,
	}, nil
}

func (s authenticationService) GetPermissions(ctx context.Context, in *pb.GetPermissionsRequest) (*pb.GetPermissionsResponse, error) {
	var resp pb.GetPermissionsResponse
	return &resp, nil
}
