package jwt_test

import (
	"github.com/ONSdigital/dp-authorisation/v2/jwt"
	"github.com/ONSdigital/dp-authorisation/v2/permissions"
	. "github.com/smartystreets/goconvey/convey"
	"testing"
)

var (
	testPublicKey                 = map[string]string{"NeKb65194Jo=": "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA0TpTemKodQNChMNj1f/NF19nMAbjKbwRENSKujO5iwXLIt0hCjh5dz4egKQo7KEr2ex3qdy50LWKD871gRfAgDoRD5/1kUUVqII5K09IDCVY/EohukrI+Uep/Z5ymPNPXXD1yJvBx/YmmuMGUAT5UKHKBCP+FcoAxYAKcaKhtL0iyVjhtD0Y4V8gcQnQq3bOYhF4FEHoHBNh23AKcJM1VvNVtSHViMuTOzsFLHAgy2lLsRLnxtXovEovAiTay+Sn1FuDOq2gswl2Uujh1GO8kfkXE1gNRn/l7RUYIRrql8kROHMSYvPBAIqYhGSWOG3JX1oFlI1erYaeIPI4l4Qj/P+YSnrRx0di3vy6ZDAnhs8kdZP81F+3rFrNUNIOVFBRKscMnvOH4HO4f9PpXynde5xTlVvqdgXVlWkxGgQk0d323ka8fPY1xsmxV99idmmgmfglPOeLxuOkFxfXJSpbP/kn9AEyKBcF2BImfc12uvdSn46zZ1f/8nvzQ9naruwEtho4t6cIb7A+5KxVAILCQHvm3xIxfxMy5RFIeR7T3KhW2URDtiGMKuEE44EQwtxXxnMUdmvBUyHg2iQ54ELD4uVVVkGZkT5cTIf8iwfWI808B+CE5T8I3YrK7DiaVkJqTWX9LqWqetwHQxY48iTN+nPguHQ6dkZwmxuWBEuQ9eECAwEAAQ=="}
	signedToken                   = "eyJraWQiOiJOZUtiNjUxOTRKbz0iLCJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYWFhYWFhYS1iYmJiLWNjY2MtZGRkZC1lZWVlZWVlZWVlZWUiLCJkZXZpY2Vfa2V5IjoiYWFhYWFhYWEtYmJiYi1jY2NjLWRkZGQtZWVlZWVlZWVlZWVlIiwiY29nbml0bzpncm91cHMiOlsiYWRtaW4iLCJwdWJsaXNoaW5nIiwiZGF0YSIsInRlc3QiXSwidG9rZW5fdXNlIjoiYWNjZXNzIiwic2NvcGUiOiJhd3MuY29nbml0by5zaWduaW4udXNlci5hZG1pbiIsImF1dGhfdGltZSI6MTU2MjE5MDUyNCwiaXNzIjoiaHR0cHM6Ly9jb2duaXRvLWlkcC51cy13ZXN0LTIuYW1hem9uYXdzLmNvbS91cy13ZXN0LTJfZXhhbXBsZSIsImV4cCI6OTk5OTk5OTk5OTk5LCJpYXQiOjE1NjIxOTA1MjQsImp0aSI6ImFhYWFhYWFhLWJiYmItY2NjYy1kZGRkLWVlZWVlZWVlZWVlZSIsImNsaWVudF9pZCI6IjU3Y2Jpc2hrNGoyNHBhYmMxMjM0NTY3ODkwIiwidXNlcm5hbWUiOiJqYW5lZG9lQGV4YW1wbGUuY29tIn0.DERwywHSkqSB3Ag-Ii8ABf0m7kyjONubFU-Z8S6tZ3F2doXGlyTisBM0Ne8zr6IpmULILk4dWgzNRBQYn9sXCOplFhdQZ2jpypUx1LZsWGKcxeOEECydQsRUr7b-MbJOBxcU7D4zP2rR4JYHp1TNI2MPnqV9B4_ZrfL0Ks4JiKOGFWUAr_ZJtQy3veUu7dSeieoVa7paPXiLvtbwvE1O7wjfzqimHX2P4JAltFgjkVTmX_UHD3wQOIE9RUR-EdHJCiWzFGhzZt48IQ-c-AyIQBtt2DcE6WzH8vIw-K0AWpcN4TRHTrkk37x9GvNRFWDYqUG5QXnglJWtpSXLrWiGJkWFB8OPBUukONLUjEVT6RrVyWH56_-MUThOvyF6SIHJkXobAxAcr8KstE2JMgeQKoyEMhKBM0sQVpyU7Z7ZIrjqryKpQqq3PoEmI0cWn-Prs79UnbKKkdo4t2Dnl1tURFl2gOCbaGAMfQGN8G0igaDgAw1C--plSKRFw460L8VkOcQcMVccIqQligOST5DICxF1RHmulNZdy8E-YrdFwz7Mi-DL8d8ZNN-fA4Jwt3Uigv5etOJE_Q3EEcx_YdbcH6Wr9UdEDXi9jZ597Shq8S5yGvXkGTV60foO01ss-Wmry0JOqEgZYBaKrFge4NsoPcN3DY5sqYGgIAHpxzt7pmI"
	invalidSignedToken            = "eyJraWQiOiJOZUtiNjUxOTRKbz0iLCJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYWFhYWFhYS1iYmJiLWNjY2MtZGRkZC1lZWVlZWVlZWVlZWUiLCJkZXZpY2Vfa2V5IjoiYWFhYWFhYWEtYmJiYi1jY2NjLWRkZGQtZWVlZWVlZWVlZWVlIiwiY29nbml0bzpncm91cHMiOlsiYWRtaW4iLCJwdWJsaXNoaW5nIiwiZGF0YSIsInRlc3QiXSwidG9rZW5fdXNlIjoiYWNjZXNzIiwic2NvcGUiOiJhd3MuY29nbml0by5zaWduaW4udXNlci5hZG1pbiIsImF1dGhfdGltZSI6MTU2MjE5MDUyNCwiaXNzIjoiaHR0cHM6Ly9jb2duaXRvLWlkcC51cy13ZXN0LTIuYW1hem9uYXdzLmNvbS91cy13ZXN0LTJfZXhhbXBsZSIsImV4cCI6OTk5OTk5OTk5OSwiaWF0IjoxNTYyMTkwNTI0LCJqdGkiOiJhYWFhYWFhYS1iYmJiLWNjY2MtZGRkZC1lZWVlZWVlZWVlZWUiLCJjbGllbnRfaWQiOiI1N2NiaXNoazRqMjRwYWJjMTIzNDU2Nzg5MCIsInVzZXJuYW1lIjoiamFuZWRvZUBleGFtcGxlLmNvbSJ9.ISW-1E4cMR-D613W-yaRQ_PBa--8YWJ3j4d0vQY9KJ-3QxiD2jpp_DnNIjPCz-jAUk-v_wifNIjcJX7q7Jyh0sDJLnVTzqclo-BtWGAYI54fHgLxsdQvQfOEpL_ONFHOc1aZHZB1UpqClVDY9X-N0D0QPNAc0qBTdcd_rEfRiVhjGGpy2KrlWEWSX6ITVtnRPeXyEqpewJwXYkbcVAjCGcArkKgFGxjwO9fq1vnH83c3VXlnNRVvHIQpcOs2WiaDIV0MsGNN7BKD_Pe5v9K2IFA7bdE1oes3rgNrp6U6zBVsnJR2OZLyhi0ZXQSW0CEJVJMuOYNMHvXlvFavvvvvvv"
	tokenNoUser                   = "eyJraWQiOiJOZUtiNjUxOTRKbz0iLCJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYWFhYWFhYS1iYmJiLWNjY2MtZGRkZC1lZWVlZWVlZWVlZWUiLCJkZXZpY2Vfa2V5IjoiYWFhYWFhYWEtYmJiYi1jY2NjLWRkZGQtZWVlZWVlZWVlZWVlIiwiY29nbml0bzpncm91cHMiOlsiYWRtaW4iLCJwdWJsaXNoaW5nIiwiZGF0YSIsInRlc3QiXSwidG9rZW5fdXNlIjoiYWNjZXNzIiwic2NvcGUiOiJhd3MuY29nbml0by5zaWduaW4udXNlci5hZG1pbiIsImF1dGhfdGltZSI6MTU2MjE5MDUyNCwiaXNzIjoiaHR0cHM6Ly9jb2duaXRvLWlkcC51cy13ZXN0LTIuYW1hem9uYXdzLmNvbS91cy13ZXN0LTJfZXhhbXBsZSIsImV4cCI6OTk5OTk5OTk5OSwiaWF0IjoxNTYyMTkwNTI0LCJqdGkiOiJhYWFhYWFhYS1iYmJiLWNjY2MtZGRkZC1lZWVlZWVlZWVlZWUiLCJjbGllbnRfaWQiOiI1N2NiaXNoazRqMjRwYWJjMTIzNDU2Nzg5MCJ9.KKPiPPLs1zPtDZPrcLgPjJheoan-v9bgXzb3zXNFz-P8y2bBXXnARwneRXkS7Q-S-nZ4sb20XsGj6KAHw4jNj3d1f7N6GIFMoOzpNNAi53jzShbGm74EcF9C6JhiLBuZChuj1KkQQ1CuOe4HbxXYsuY3wahnWIG8loZ4WTn-OiQ1sG8wK5KN1i53hBvfQMLY9dWkq2pJRl6x15noMeqMBiG1XpR_kxit3EpcZGQMtlJImp0lflb0NGKzunw4aVajH-sfuyAWzAkggvroQcl4_9cDjSar6-J7EzUsHvrrXVXUyBdO2Zdge1XKpHF1gY-He1xYUz4S1Dp_uR-3CPhpdwqpj3bF4mnycLIXMjm-wpDGoFaz5iHtbarlz8PffEJvVJE6rr_JxEP4_iLWikdsgXSjaqoMEgV_wOv2NF-vDt-QT76atSrT0R5KqqzKoVmzhqbOneRW2zD1f0cx10N38wPLcUbzMKN2pD-Ig3nwX5wh6Wx6W4SCKNe7Dtj5nCnlIaEN6ALnd6EBFStH-6VSQWnoOMx3AF1M_uiMkZUh2XS5GvU4ELCatrKsoqe1z67RvKjr8eROpbuBV4SheTdnFEQF-nPHs5X0nDplobcOT6NlB22Guf8s7RaHPV_wdvRqY8S2t2SWGtXRW20SiEB0wEU1DzC2-HDGjbEjkH9Xdbo"
	tokenNoGroups                 = "eyJraWQiOiJOZUtiNjUxOTRKbz0iLCJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYWFhYWFhYS1iYmJiLWNjY2MtZGRkZC1lZWVlZWVlZWVlZWUiLCJkZXZpY2Vfa2V5IjoiYWFhYWFhYWEtYmJiYi1jY2NjLWRkZGQtZWVlZWVlZWVlZWVlIiwidG9rZW5fdXNlIjoiYWNjZXNzIiwic2NvcGUiOiJhd3MuY29nbml0by5zaWduaW4udXNlci5hZG1pbiIsImF1dGhfdGltZSI6MTU2MjE5MDUyNCwiaXNzIjoiaHR0cHM6Ly9jb2duaXRvLWlkcC51cy13ZXN0LTIuYW1hem9uYXdzLmNvbS91cy13ZXN0LTJfZXhhbXBsZSIsImV4cCI6OTk5OTk5OTk5OSwiaWF0IjoxNTYyMTkwNTI0LCJqdGkiOiJhYWFhYWFhYS1iYmJiLWNjY2MtZGRkZC1lZWVlZWVlZWVlZWUiLCJjbGllbnRfaWQiOiI1N2NiaXNoazRqMjRwYWJjMTIzNDU2Nzg5MCIsInVzZXJuYW1lIjoiamFuZWRvZUBleGFtcGxlLmNvbSJ9.JYCCSU4ftZavwWlpmyNv39GOwbHqcgvYyKhwci0ezYeYh4ksowHcROw71zhf5zd5GS5hVa9rop9-ULayysR09vTKhX_IPB5q3VDNyQpI3cpZGK7pN2IHqHfA9t3Khl7iydbTF8nUSi81wvtdV4qZngSD1OQih_IAo4M3MU6szbMeNGCrxyIq2Oed6vz0cXlo6dLLmlTInOPPqvewNWReL5HXo-AZAchVozAcSmt87dI15eRuB6sTo_lqOZ7WHeDjLw4reLG0_145Cogh4FwF103VsKvlHkJuk1Jx_UZuFPxJXoXFAs4D_mG8mGceGcGsChImGya5Jnr9jfGmqLOl3lBNW8cWWuePPhJBSvz_A9NHC8sWCoqwZA7pscSwcb1yKtxDVkAfBXW5aZ72gj6zLEnqKbDJG2Loox6h3haSXKdKbh_cGNdRJOPcKMokiskXorBbalWji1XXRKSTuax0l5tPA_pYPfLNSx3pfVIHlnk52nVRVyv2Z0na227ie_uTrhoK_oAU2xWFuOUYFK2t-aCyOwR5EdgtbMYUePwe9cLkMjqM2lCzThHO5shhzlXhjBqvTTYeBudv3FR7g4cFWFuzOk7ZVXOzteltqojoQw2RUE7rfbhFN2Wf-cpo1_FHj6cEbtj9e6d3G-oAkGFWU6iGkb5tf1h0gZJxAWsQ7FM"
	tokenExpiredTime              = "eyJraWQiOiJOZUtiNjUxOTRKbz0iLCJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYWFhYWFhYS1iYmJiLWNjY2MtZGRkZC1lZWVlZWVlZWVlZWUiLCJkZXZpY2Vfa2V5IjoiYWFhYWFhYWEtYmJiYi1jY2NjLWRkZGQtZWVlZWVlZWVlZWVlIiwiY29nbml0bzpncm91cHMiOlsiYWRtaW4iLCJwdWJsaXNoaW5nIiwiZGF0YSIsInRlc3QiXSwidG9rZW5fdXNlIjoiYWNjZXNzIiwic2NvcGUiOiJhd3MuY29nbml0by5zaWduaW4udXNlci5hZG1pbiIsImF1dGhfdGltZSI6MTU2MjE5MDUyNCwiaXNzIjoiaHR0cHM6Ly9jb2duaXRvLWlkcC51cy13ZXN0LTIuYW1hem9uYXdzLmNvbS91cy13ZXN0LTJfZXhhbXBsZSIsImV4cCI6OTk5OSwiaWF0IjoxNTYyMTkwNTI0LCJqdGkiOiJhYWFhYWFhYS1iYmJiLWNjY2MtZGRkZC1lZWVlZWVlZWVlZWUiLCJjbGllbnRfaWQiOiI1N2NiaXNoazRqMjRwYWJjMTIzNDU2Nzg5MCIsInVzZXJuYW1lIjoiamFuZWRvZUBleGFtcGxlLmNvbSJ9.A7JpBk_cs9iXfRcVnzzt5BM1eErYCwww8x_jclgQEyJ_ZceJ0N6jWEycpvuLXQud4-pUGagKZ4cZYrh7KAz8ISkR_pJhTrN7V9tXxT2e35M4G_1nPBEkB5pPaNTynzhg0F-PYTPAHCRyehDuEXqf_xzGzxRdZC37RyJQK_uK48p_LswKDcZVHCe-ePddvqn0je_GkImaJenI4guU5waqht7RwdUvE-0Qfc1feWDIGeIG0qRUQ__beq4ymoV7aAnIJ-nTJyYpvvgAFv9xoA9kcXP30ZWdan90N0BxWgvAji1Jf02e6LpgOsXvFySqtAC0Lg6EB-i3MTLAZiIQLgJ9qzW0s9j6TuVchwvoysNAC9wHP1QEkMT2bTNOkGqDgEUbEwgcTF7ATo-5xeGdtoKyZmk2j4sdGM5EdZZFRlKBDEKFIZehDMYgeaYPbR7WStpWiaRO91TVN3-5OYV3IKgaHEGfny1gkI7pJs4KLEguXLGPuGlsGgHLlya62DYBFoPVGUZodGO6oifHknZbSZBizzyhBUm5voWiFel9cqVcAfHirveYPlnPxlvCVVnNp4ZoA-UK1dJLf2RZvWCef2gfWIT8sQs5e6SpYWeZrf2Qb2D8Yb1IceZuLCOaOl3UnNLjB0HYhhNKRKZCHcWqBDB9ofjSa4Grjj7jSmZgIRNdR2I"
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
		publicKey := map[string]string{"kid": "this should not be a valid key"}

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
