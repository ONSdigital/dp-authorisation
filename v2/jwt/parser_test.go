package jwt_test

import (
	"github.com/ONSdigital/dp-authorisation/v2/jwt"
	"github.com/ONSdigital/dp-authorisation/v2/permissions"
	. "github.com/smartystreets/goconvey/convey"
	"testing"
)

var (
	testPublicKey                 = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u+qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyehkd3qqGElvW/VDL5AaWTg0nLVkjRo9z+40RQzuVaE8AkAFmxZzow3x+VJYKdjykkJ0iT9wCS0DRTXu269V264Vf/3jvredZiKRkgwlL9xNAwxXFg0x/XFw005UWVRIkdgcKWTjpBP2dPwVZ4WWC+9aGVd+Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbcmwIDAQAB"
	signedToken                   = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYWFhYWFhYS1iYmJiLWNjY2MtZGRkZC1lZWVlZWVlZWVlZWUiLCJkZXZpY2Vfa2V5IjoiYWFhYWFhYWEtYmJiYi1jY2NjLWRkZGQtZWVlZWVlZWVlZWVlIiwiY29nbml0bzpncm91cHMiOlsiYWRtaW4iLCJwdWJsaXNoaW5nIiwiZGF0YSIsInRlc3QiXSwidG9rZW5fdXNlIjoiYWNjZXNzIiwic2NvcGUiOiJhd3MuY29nbml0by5zaWduaW4udXNlci5hZG1pbiIsImF1dGhfdGltZSI6MTU2MjE5MDUyNCwiaXNzIjoiaHR0cHM6Ly9jb2duaXRvLWlkcC51cy13ZXN0LTIuYW1hem9uYXdzLmNvbS91cy13ZXN0LTJfZXhhbXBsZSIsImV4cCI6OTk5OTk5OTk5OTk5LCJpYXQiOjE1NjIxOTA1MjQsImp0aSI6ImFhYWFhYWFhLWJiYmItY2NjYy1kZGRkLWVlZWVlZWVlZWVlZSIsImNsaWVudF9pZCI6IjU3Y2Jpc2hrNGoyNHBhYmMxMjM0NTY3ODkwIiwidXNlcm5hbWUiOiJqYW5lZG9lQGV4YW1wbGUuY29tIn0.T-_A16e5yMP8zTlUR63DdefgdE8F_YapSODsYsV534dM1deGEXtcv9A_W5mSACNeWfhDZdOfIhEhKKv-ov5nTjSVOcpvHVPSyotFMo7nt0RJCmoXEfsh0q8yoF2ZFqatDbN33wyZEb9SFhnFy0wQXcQAHW1iMLpsffLAFJ0ApSMvCTddo71rmRr2duCPT0svUTzdgX33pwoR6_gPGH18kQvEuYb0h9wseNVmSveHzgQ_nRTEg6OVA2gdxDZU9OqsQRa6mhlHs4ma0F63T_j6cDc2erj1SOs9dvekZXTL8VjrlKUpFImKBsc_LcZy0TwhJUO_M6SOq-ulQLXL_-OPAw"
	invalidSignedToken            = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYWFhYWFhYS1iYmJiLWNjY2MtZGRkZC1lZWVlZWVlZWVlZWUiLCJkZXZpY2Vfa2V5IjoiYWFhYWFhYWEtYmJiYi1jY2NjLWRkZGQtZWVlZWVlZWVlZWVlIiwiY29nbml0bzpncm91cHMiOlsiYWRtaW4iLCJwdWJsaXNoaW5nIiwiZGF0YSIsInRlc3QiXSwidG9rZW5fdXNlIjoiYWNjZXNzIiwic2NvcGUiOiJhd3MuY29nbml0by5zaWduaW4udXNlci5hZG1pbiIsImF1dGhfdGltZSI6MTU2MjE5MDUyNCwiaXNzIjoiaHR0cHM6Ly9jb2duaXRvLWlkcC51cy13ZXN0LTIuYW1hem9uYXdzLmNvbS91cy13ZXN0LTJfZXhhbXBsZSIsImV4cCI6OTk5OTk5OTk5OSwiaWF0IjoxNTYyMTkwNTI0LCJqdGkiOiJhYWFhYWFhYS1iYmJiLWNjY2MtZGRkZC1lZWVlZWVlZWVlZWUiLCJjbGllbnRfaWQiOiI1N2NiaXNoazRqMjRwYWJjMTIzNDU2Nzg5MCIsInVzZXJuYW1lIjoiamFuZWRvZUBleGFtcGxlLmNvbSJ9.ISW-1E4cMR-D613W-yaRQ_PBa--8YWJ3j4d0vQY9KJ-3QxiD2jpp_DnNIjPCz-jAUk-v_wifNIjcJX7q7Jyh0sDJLnVTzqclo-BtWGAYI54fHgLxsdQvQfOEpL_ONFHOc1aZHZB1UpqClVDY9X-N0D0QPNAc0qBTdcd_rEfRiVhjGGpy2KrlWEWSX6ITVtnRPeXyEqpewJwXYkbcVAjCGcArkKgFGxjwO9fq1vnH83c3VXlnNRVvHIQpcOs2WiaDIV0MsGNN7BKD_Pe5v9K2IFA7bdE1oes3rgNrp6U6zBVsnJR2OZLyhi0ZXQSW0CEJVJMuOYNMHvXlvFavvvvvvv"
	tokenNoUser                   = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYWFhYWFhYS1iYmJiLWNjY2MtZGRkZC1lZWVlZWVlZWVlZWUiLCJkZXZpY2Vfa2V5IjoiYWFhYWFhYWEtYmJiYi1jY2NjLWRkZGQtZWVlZWVlZWVlZWVlIiwiY29nbml0bzpncm91cHMiOlsiYWRtaW4iLCJwdWJsaXNoaW5nIiwiZGF0YSIsInRlc3QiXSwidG9rZW5fdXNlIjoiYWNjZXNzIiwic2NvcGUiOiJhd3MuY29nbml0by5zaWduaW4udXNlci5hZG1pbiIsImF1dGhfdGltZSI6MTU2MjE5MDUyNCwiaXNzIjoiaHR0cHM6Ly9jb2duaXRvLWlkcC51cy13ZXN0LTIuYW1hem9uYXdzLmNvbS91cy13ZXN0LTJfZXhhbXBsZSIsImV4cCI6OTk5OTk5OTk5OSwiaWF0IjoxNTYyMTkwNTI0LCJqdGkiOiJhYWFhYWFhYS1iYmJiLWNjY2MtZGRkZC1lZWVlZWVlZWVlZWUiLCJjbGllbnRfaWQiOiI1N2NiaXNoazRqMjRwYWJjMTIzNDU2Nzg5MCJ9.HlaNy7soqePVoh13Zo_tKKU9c3M1c_McGVluhusqw2ev165yeM0hCAWeto9ad-acpo086gx2Hrb7eUibuSTJTsQ9Gpnf_Sk8VsMxeBHqMLF8oRIfBqDeDMOOP-BB7yhZ4jp4oAhLYZxgTJ58gPIYzx4gxeiCh9Vt_bixv4T0T6_egcSSsyfv6DDj115CLCDE3mfG3I4Ul4vp-P9-RuGwkYxSUpZGHo2EhTl5uCQWk_Gex1L8pUmlXcO3plTuepzEfdHcNvtzBbVtBv79v6jScKibXjG--d2fIDRSIAucC2G3PFR8htO7RlQngfQGcC_VO5H7ofnoKvzsW9M0ORY5_w"
	tokenNoGroups                 = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYWFhYWFhYS1iYmJiLWNjY2MtZGRkZC1lZWVlZWVlZWVlZWUiLCJkZXZpY2Vfa2V5IjoiYWFhYWFhYWEtYmJiYi1jY2NjLWRkZGQtZWVlZWVlZWVlZWVlIiwidG9rZW5fdXNlIjoiYWNjZXNzIiwic2NvcGUiOiJhd3MuY29nbml0by5zaWduaW4udXNlci5hZG1pbiIsImF1dGhfdGltZSI6MTU2MjE5MDUyNCwiaXNzIjoiaHR0cHM6Ly9jb2duaXRvLWlkcC51cy13ZXN0LTIuYW1hem9uYXdzLmNvbS91cy13ZXN0LTJfZXhhbXBsZSIsImV4cCI6OTk5OTk5OTk5OSwiaWF0IjoxNTYyMTkwNTI0LCJqdGkiOiJhYWFhYWFhYS1iYmJiLWNjY2MtZGRkZC1lZWVlZWVlZWVlZWUiLCJjbGllbnRfaWQiOiI1N2NiaXNoazRqMjRwYWJjMTIzNDU2Nzg5MCIsInVzZXJuYW1lIjoiamFuZWRvZUBleGFtcGxlLmNvbSJ9.OzKxQepc9edr2QcFjo0txsFgmKJqznxIg75bYdYYy3eeHNIubLSww5pIBaFSXZqeTVDYG-_bjy9brMiiOg53DWoX17BDGsAPBwrMNPoPiH_WjnvDIQ4lVxT7j8M0Y34WNrxJJ-n08vUfvWUJbV4DIff4eV6eBmMIPOeakLESatGj5jOFAvxesOjlTn5rWO03Urfl_9ph4WV5wNFDleW0MBdc27yDiEERCmfqc-2X3SMgZcCFE8CqO0yUGkwfIe9z1kPHUHZXzu6_0ga7sIO_K8goZuixOYu6NYygAxbxT8_Im9nrO5MRsGipDwL_RRZlPz1HzFRV_1NV4F3g0FoRlQ"
	tokenExpiredTime              = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYWFhYWFhYS1iYmJiLWNjY2MtZGRkZC1lZWVlZWVlZWVlZWUiLCJkZXZpY2Vfa2V5IjoiYWFhYWFhYWEtYmJiYi1jY2NjLWRkZGQtZWVlZWVlZWVlZWVlIiwiY29nbml0bzpncm91cHMiOlsiYWRtaW4iLCJwdWJsaXNoaW5nIiwiZGF0YSIsInRlc3QiXSwidG9rZW5fdXNlIjoiYWNjZXNzIiwic2NvcGUiOiJhd3MuY29nbml0by5zaWduaW4udXNlci5hZG1pbiIsImF1dGhfdGltZSI6MTU2MjE5MDUyNCwiaXNzIjoiaHR0cHM6Ly9jb2duaXRvLWlkcC51cy13ZXN0LTIuYW1hem9uYXdzLmNvbS91cy13ZXN0LTJfZXhhbXBsZSIsImV4cCI6OTk5OSwiaWF0IjoxNTYyMTkwNTI0LCJqdGkiOiJhYWFhYWFhYS1iYmJiLWNjY2MtZGRkZC1lZWVlZWVlZWVlZWUiLCJjbGllbnRfaWQiOiI1N2NiaXNoazRqMjRwYWJjMTIzNDU2Nzg5MCIsInVzZXJuYW1lIjoiamFuZWRvZUBleGFtcGxlLmNvbSJ9.MlQOUTQBld9WX6v6n8P24_9MUDNwhk8501Vf1BYsFhJigfaSLqNtP1mxnaycecLL2fzTq57pVKpUVEANNoOCUQnblXz9yRVryI0pNMbFM-CFtE47dP4f5UDrALcT00B9SFcWjAXCtilt5mJwYIZnEgNh5fQylLFPxaUeAuMZej4ndDVqZmaJ2LnY1PbLsR24SM8C-06EebM_dMLDzm4qvKFsnfVL5jFIUkW5_iXM78Bq_Zkdw0QsVGJm-K0AVsvucp9lf1oJytWJDsIKZxSRUIicquhYK-3QYb0_lTUIScKWxydnRn9UH9fhID8m7JoFzdj7uVkaltVnvDuQxRW_cw"
	tokenMalformed                = "this.is.a.malformed.token"
	tokenUnsupportedEncryptionAlg = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYWFhYWFhYS1iYmJiLWNjY2MtZGRkZC1lZWVlZWVlZWVlZWUiLCJkZXZpY2Vfa2V5IjoiYWFhYWFhYWEtYmJiYi1jY2NjLWRkZGQtZWVlZWVlZWVlZWVlIiwiY29nbml0bzpncm91cHMiOlsiYWRtaW4iLCJwdWJsaXNoaW5nIiwiZGF0YSIsInRlc3QiXSwidG9rZW5fdXNlIjoiYWNjZXNzIiwic2NvcGUiOiJhd3MuY29nbml0by5zaWduaW4udXNlci5hZG1pbiIsImF1dGhfdGltZSI6MTU2MjE5MDUyNCwiaXNzIjoiaHR0cHM6Ly9jb2duaXRvLWlkcC51cy13ZXN0LTIuYW1hem9uYXdzLmNvbS91cy13ZXN0LTJfZXhhbXBsZSIsImV4cCI6OTk5OSwiaWF0IjoxNTYyMTkwNTI0LCJqdGkiOiJhYWFhYWFhYS1iYmJiLWNjY2MtZGRkZC1lZWVlZWVlZWVlZWUiLCJjbGllbnRfaWQiOiI1N2NiaXNoazRqMjRwYWJjMTIzNDU2Nzg5MCIsInVzZXJuYW1lIjoiamFuZWRvZUBleGFtcGxlLmNvbSJ9.ukQEP4Iej3jNbnoWivP2PRh0TEiD_3oIAr-hFHoK5tw"
	expectedUser                  = "janedoe@example.com"
)

func TestCognitoRSAParser_NewCognitoRSAParser(t *testing.T) {
	Convey("Given a valid base64 encoded public key", t, func() {
		publicKey := testPublicKey

		Convey("When NewCognitoRSAParser is called", func() {
			parser, err := jwt.NewCognitoRSAParser(publicKey)

			Convey("Then there is no error returned", func() {
				So(err, ShouldBeNil)
			})

			Convey("Then the expected parser instance is returned", func() {
				So(parser, ShouldNotBeNil)
			})
		})
	})
}

func TestCognitoRSAParser_NewCognitoRSAParser_InvalidPublicKey(t *testing.T) {
	Convey("Given an invalid base64 encoded public key", t, func() {
		publicKey := "this should not be a valid key"

		Convey("When NewCognitoRSAParser is called", func() {
			parser, err := jwt.NewCognitoRSAParser(publicKey)

			Convey("Then an error is returned", func() {
				So(err, ShouldNotBeNil)
				So(err, ShouldEqual, jwt.ErrFailedToParsePublicKey)
			})

			Convey("Then the parser is nil", func() {
				So(parser, ShouldBeNil)
			})
		})
	})
}

func TestCognitoRSAParser_Parse(t *testing.T) {
	p, _ := jwt.NewCognitoRSAParser(testPublicKey)
	expectedEntityData := &permissions.EntityData{
		UserID: expectedUser,
		Groups: []string{"admin", "publishing", "data", "test"},
	}

	Convey("Given a valid JWT token", t, func() {
		jwtToken := signedToken

		Convey("When Parse is called", func() {
			entityData, err := p.Parse(jwtToken)

			Convey("Then there is no error returned", func() {
				So(err, ShouldBeNil)
			})

			Convey("Then the expected entity data is returned", func() {
				So(entityData, ShouldNotBeNil)
				So(entityData, ShouldResemble, expectedEntityData)
			})
		})
	})
}

func TestCognitoRSAParser_Parse_InvalidSignedToken(t *testing.T) {
	p, _ := jwt.NewCognitoRSAParser(testPublicKey)

	Convey("Given a JWT token that is not correctly signed", t, func() {
		jwtToken := invalidSignedToken

		Convey("When Parse is called", func() {
			entityData, err := p.Parse(jwtToken)

			Convey("Then the expected error is returned", func() {
				So(err, ShouldNotBeNil)
				So(err, ShouldEqual, jwt.ErrInvalidSignature)
			})

			Convey("Then the entity data is nil", func() {
				So(entityData, ShouldBeNil)
			})
		})
	})
}

func TestCognitoRSAParser_Parse_ExpiredToken(t *testing.T) {
	p, _ := jwt.NewCognitoRSAParser(testPublicKey)

	Convey("Given a JWT token that has expired", t, func() {
		jwtToken := tokenExpiredTime

		Convey("When Parse is called", func() {
			entityData, err := p.Parse(jwtToken)

			Convey("Then the expected error is returned", func() {
				So(err, ShouldNotBeNil)
				So(err, ShouldEqual, jwt.ErrTokenExpired)
			})

			Convey("Then the entity data is nil", func() {
				So(entityData, ShouldBeNil)
			})
		})
	})
}

func TestCognitoRSAParser_Parse_MalformedToken(t *testing.T) {
	p, _ := jwt.NewCognitoRSAParser(testPublicKey)

	Convey("Given a JWT token that has expired", t, func() {
		jwtToken := tokenMalformed

		Convey("When Parse is called", func() {
			entityData, err := p.Parse(jwtToken)

			Convey("Then the expected error is returned", func() {
				So(err, ShouldNotBeNil)
				So(err, ShouldEqual, jwt.ErrTokenMalformed)
			})

			Convey("Then the entity data is nil", func() {
				So(entityData, ShouldBeNil)
			})
		})
	})
}

func TestCognitoRSAParser_Parse_UnsupportedEncryptionToken(t *testing.T) {
	p, _ := jwt.NewCognitoRSAParser(testPublicKey)

	Convey("Given a JWT token that uses an encryption algorithm other than the supported RSA", t, func() {
		jwtToken := tokenUnsupportedEncryptionAlg

		Convey("When Parse is called", func() {
			entityData, err := p.Parse(jwtToken)

			Convey("Then the expected error is returned", func() {
				So(err, ShouldNotBeNil)
				So(err.Error(), ShouldEqual, jwt.ErrTokenUnsupportedEncryption.Error())
			})

			Convey("Then the entity data is nil", func() {
				So(entityData, ShouldBeNil)
			})
		})
	})
}

func TestCognitoRSAParser_Parse_TokenWithoutUserID(t *testing.T) {
	p, _ := jwt.NewCognitoRSAParser(testPublicKey)

	Convey("Given a JWT token that has no user ID", t, func() {
		jwtToken := tokenNoUser

		Convey("When Parse is called", func() {
			entityData, err := p.Parse(jwtToken)

			Convey("Then the expected error is returned", func() {
				So(err, ShouldNotBeNil)
				So(err, ShouldEqual, jwt.ErrNoUserID)
			})

			Convey("Then the entity data is nil", func() {
				So(entityData, ShouldBeNil)
			})
		})
	})
}

func TestCognitoRSAParser_Parse_TokenWithoutGroups(t *testing.T) {
	p, _ := jwt.NewCognitoRSAParser(testPublicKey)

	Convey("Given a JWT token that has no groups", t, func() {
		jwtToken := tokenNoGroups

		Convey("When Parse is called", func() {
			entityData, err := p.Parse(jwtToken)

			Convey("Then the expected error is returned", func() {
				So(err, ShouldNotBeNil)
				So(err, ShouldEqual, jwt.ErrNoGroups)
			})

			Convey("Then the entity data is nil", func() {
				So(entityData, ShouldBeNil)
			})
		})
	})
}
