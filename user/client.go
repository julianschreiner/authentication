package user

import (
	pb "authentication"
	"context"
	"errors"
	"google.golang.org/grpc"
	"log"
)

const NormalUserId = 3
const rpcDial = "user-uas:5040"

type UserClient interface {
	GetActiveUserByEmail(email string) (*User, error)
	GetActiveUserById(id uint64) (*User, error)
	CreateUser(user *User) (*User, error)
}

type userClient struct {
	client pb.UserClient
}

func NewUserClient() UserClient {
	var conn *grpc.ClientConn
	conn, err := grpc.Dial(rpcDial, grpc.WithInsecure())
	if err != nil {
		log.Fatalf("did not connect: %s", err)
	}
	log.Printf("grpc onnection %f", conn)
	//defer conn.Close()

	client := pb.NewUserClient(conn)

	return &userClient{
		client: client,
	}
}

func (u *userClient) GetActiveUserByEmail(email string) (*User, error) {
	response, err := u.client.GetUserInformationEmail(context.Background(), &pb.GetUserInformationEmailRequest{
		Email: email,
	})
	if err != nil {
		log.Fatalf("Error when calling GetUserInformationEmail: %s", err)
		return nil, err
	}

	log.Printf("[GET per E-mail] Response from server: %s", response)
	if response.Size() > 0 {
		if response.User.Size() > 0 {
			user := User{
				Id:       uint(response.User.Id),
				Email:    response.User.Email,
				Password: "",
				Role:     uint(response.User.Role),
				Dob:      response.User.Dob,
				Active:   response.User.Active,
				Forename: response.User.Forename,
				Surname:  response.User.Surname,
			}
			return &user, nil
		}
	}

	return nil, nil
}

func (u *userClient) GetActiveUserById(id uint64) (*User, error) {
	response, err := u.client.GetUserInformation(context.Background(), &pb.GetUserInformationRequest{
		Id: id,
	})
	if err != nil {
		log.Fatalf("Error when calling GetUserInformation: %s", err)
		return nil, err
	}

	log.Printf("[GET per ID] Response from server: %s", response)
	if response.Size() > 0 {
		if response.User.Size() > 0 {
			user := User{
				Id:       uint(response.User.Id),
				Email:    response.User.Email,
				Password: "",
				Role:     uint(response.User.Role),
				Dob:      response.User.Dob,
				Active:   response.User.Active,
				Forename: response.User.Forename,
				Surname:  response.User.Surname,
			}
			return &user, nil
		}
	}

	return nil, nil
}

func (u *userClient) CreateUser(user *User) (*User, error) {
	response, err := u.client.CreateUser(context.Background(), &pb.CreateUserRequest{
		Email:    user.Email,
		Forename: user.Forename,
		Surname:  user.Surname,
		Dob:      user.Dob,
		Role:     NormalUserId,
	})
	if err != nil {
		log.Fatalf("Error when calling CreateUser: %s", err)
		return nil, err
	}

	log.Printf("[Create User] Response from server: %s", response)

	if response.Size() <= 0 && response.User.Size() <= 0 {
		return nil, errors.New("Something went wrong. User creation.")
	}

	usr := &User{
		Id:        uint(response.User.Id),
		Email:     response.User.Email,
		Role:      uint(response.User.Role),
		CreatedAt: response.User.CreatedAt,
		Dob:       response.User.Dob,
		Active:    response.User.Active,
		Forename:  response.User.Forename,
		Surname:   response.User.Surname,
	}

	return usr, nil
}
