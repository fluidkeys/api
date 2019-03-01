.PHONY: run
run:
	firejail --seccomp.drop=sendfile realize start

.PHONY: run_collectors
run_collectors:
	go run main.go collect

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
