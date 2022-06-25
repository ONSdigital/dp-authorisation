package authorisationtest

// The following JWT tokens have been generated for use in tests.
// They can be verified using the default public key provided in the configuration.

var (
	// AdminJWTToken is a valid JWT token that contains the administrator group 'groups/role-admin'.
	AdminJWTToken = "Bearer eyJraWQiOiJOZUtiNjUxOTRKbz0iLCJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYWFhYWFhYS1iYmJiLWNjY2MtZGRkZC1lZWVlZWVlZWVlZWUiLCJkZXZpY2Vfa2V5IjoiYWFhYWFhYWEtYmJiYi1jY2NjLWRkZGQtZWVlZWVlZWVlZWVlIiwiY29nbml0bzpncm91cHMiOlsicm9sZS1hZG1pbiJdLCJ0b2tlbl91c2UiOiJhY2Nlc3MiLCJzY29wZSI6ImF3cy5jb2duaXRvLnNpZ25pbi51c2VyLmFkbWluIiwiYXV0aF90aW1lIjoxNTYyMTkwNTI0LCJpc3MiOiJodHRwczovL2NvZ25pdG8taWRwLnVzLXdlc3QtMi5hbWF6b25hd3MuY29tL3VzLXdlc3QtMl9leGFtcGxlIiwiZXhwIjo5OTk5OTk5OTk5OTksImlhdCI6MTU2MjE5MDUyNCwianRpIjoiYWFhYWFhYWEtYmJiYi1jY2NjLWRkZGQtZWVlZWVlZWVlZWVlIiwiY2xpZW50X2lkIjoiNTdjYmlzaGs0ajI0cGFiYzEyMzQ1Njc4OTAiLCJ1c2VybmFtZSI6ImphbmVkb2VAZXhhbXBsZS5jb20ifQ.ZmZkZlrAtFxG5PnfC7dOru_KykJJ5f5bu7YkpCaNMwjXtBM8hWmiWk88QGfbx9kqI1wYs479cFrZ0FablR_38ek6RH9yAVaxTk7ZKOBUqSbVbIB-82B5iRXI8vLquZYjZEunH7LDv0kfZbsqoCZCe3nAJU5aV-hVMF1Cbz2LgIymRqMFqDxD2YIu5RgRHc71FtPebNfMTFCmnTs2v5b4KOqDNZZuab7eLMc-B941M6XyfdF7I6RRfvxw7xTv-qi6ZhGzkbe7K2rlxUmSwjQRDPYrOD7qji_V7yxon9okPyvpTHp-8yaHyrVv1CUCHX67c3OSRT7x3gZqRcPYpEZmScyj7M38Kwn04CKcNqc4ouozIBqhtkBgnCWJuaj1wl7AxQDRR5_F_IS962Y8t2IfU-UurqoZAZvQqWWyeBVJB3aIKrhSJHx62ayZVjd3u2za2WS8aZT97pjEuKLjSoYcgdEqnL9_fKdZc4Vv3QBZmtj_rZsb-zOrj2u_kMox8g-uaIC6ehkNucmM-HEfSuTA7nf_pPNw9c6HLDXJizGWMBVf18K94HPFTyWtJWB7yhXCuV9Kulp9iVGEn8230e6mn7ui0z8lU8R-KpZm3_aPTXBXKsUVdsoj0ZK5sd4y5ARdZ5BOGurT5NpMsw8avW-CqMF0dPY2kmUv3EtBE6dkvdg" //nolint:gosec

	// PublisherJWTToken is a valid JWT token that contains the publisher group 'groups/role-admin'.
	PublisherJWTToken = "Bearer eyJraWQiOiJOZUtiNjUxOTRKbz0iLCJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYWFhYWFhYS1iYmJiLWNjY2MtZGRkZC1lZWVlZWVlZWVlZWUiLCJkZXZpY2Vfa2V5IjoiYWFhYWFhYWEtYmJiYi1jY2NjLWRkZGQtZWVlZWVlZWVlZWVlIiwiY29nbml0bzpncm91cHMiOlsicm9sZS1wdWJsaXNoZXIiXSwidG9rZW5fdXNlIjoiYWNjZXNzIiwic2NvcGUiOiJhd3MuY29nbml0by5zaWduaW4udXNlci5hZG1pbiIsImF1dGhfdGltZSI6MTU2MjE5MDUyNCwiaXNzIjoiaHR0cHM6Ly9jb2duaXRvLWlkcC51cy13ZXN0LTIuYW1hem9uYXdzLmNvbS91cy13ZXN0LTJfZXhhbXBsZSIsImV4cCI6OTk5OTk5OTk5OTk5LCJpYXQiOjE1NjIxOTA1MjQsImp0aSI6ImFhYWFhYWFhLWJiYmItY2NjYy1kZGRkLWVlZWVlZWVlZWVlZSIsImNsaWVudF9pZCI6IjU3Y2Jpc2hrNGoyNHBhYmMxMjM0NTY3ODkwIiwidXNlcm5hbWUiOiJqYW5lZG9lQGV4YW1wbGUuY29tIn0.NdA6p2ViFFw2QOJj3N8g8C2jhf1iV0I_-PQAZrgvQuzU6JQGhGetRrWUObCyKzBWn8mSFPIuhM_sAyuPx2aQHX0SV56xNbWkIufWLAf1e5bB_Jsa3o19F2F6U1W-RvxAjULQRPvqhbMYj8WDm2gbJs6WrGf5TD0bqDYvK5A7zKcxRVe57nONqIMlwiC9ajc2PbU3JITGkYqLKBQmgaKL5Kb-lDnZWBCaSI7YSZNHh1nhgINST-wzhUNNYUL6CqTpo5Icii4lnSl7teE9UdhqrvOD1DyF6A_9gukIsSEcZ3S40aI5ELKG-jbOh6BBT7UPFdoCV0VkyULCLuVQz5XV0gelwzUnGQk9J2cgV9gZrziHXx8a3oeJwKbbp26qySBiAXtiHIfnTkPcF6yv6fm2-pKQDmVDIXq3ckmDbVj2cQKFbiiycffZJTwKquyO27Wc4SD9Waygaa3O8KC-SAuIPGzVwO8lVBjSt8NUgdnWG-vIsn1GCYfAH76hLw7FS-EI07oj-2KssHuz3hWvqWW1djt-FJYmykLiQ7SCRvA6hZq7ccIQVo8zKlQjp2Q5f7ujsjAMW-w69xspF5Nq4PgHQZvvCmXR7HvGI5477Ayoc83ks5tfC_AtPTiExlpl6DEuw1_Uj7nxwRho5Yvt3fFQqNycKiYoCPK1Sfz8WHsRpSE" //nolint:gosec

	// ZebedeeServiceToken is a non-JWT old world service token that the library is going to have to be able to handle for transitional support
	ZebedeeServiceToken = "Bearer 5c227034be6e2c9acca6018808fec9fbd1490a5128d7c74dd8b16d1f001b4b05" //nolint:gosec
)
