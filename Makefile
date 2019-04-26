.PHONY: run
run:
	firejail --seccomp.drop=sendfile realize start

.PHONY: print_expired_keys
print_expired_keys:
	go run main.go print_expired_keys

.PHONY: delete_expired_keys
delete_expired_keys:
	go run main.go delete_expired_keys

.PHONY: send_emails
send_emails:
	go run main.go send_emails

.PHONY: migrate
migrate:
	go run main.go migrate

.PHONY: test
test:
	go test -v -failfast ./...
	find . -name '*.go' -not -path './vendor/*' -exec golint {} \;

.PHONY: jenkins_deploy_to_heroku
jenkins_deploy_to_heroku:
	heroku git:remote --app fluidkeys-api
	git push heroku HEAD:master
