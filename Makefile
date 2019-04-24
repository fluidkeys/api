.PHONY: run
run:
	firejail --seccomp.drop=sendfile realize start

.PHONY: print_expired_keys
print_expired_keys:
	go run cmd/printexpiredkeys/printexpiredkeys.go

.PHONY: send_emails
send_emails:
	go run cmd/sendemails/sendemails.go

.PHONY: migrate
migrate:
	go run cmd/migrate/migrate.go

.PHONY: test
test:
	go test -v -failfast ./...
	find . -name '*.go' -not -path './vendor/*' -exec golint {} \;

.PHONY: jenkins_deploy_to_heroku
jenkins_deploy_to_heroku:
	heroku git:remote --app fluidkeys-api
	git push heroku HEAD:master
