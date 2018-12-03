.PHONY: run
run:
	firejail --seccomp.enotsup=sendfile realize start

.PHONY: run_collectors
run_collectors:
	go run main.go collect

.PHONY: migrate
migrate:
	./migrations/migrate migrations/*.sql

.PHONY: migrate_heroku
migrate_heroku:
	MIGRATE_HEROKU=1 ./migrations/migrate migrations/*.sql

.PHONY: test
test:
	go build main.go

.PHONY: jenkins_deploy_to_heroku
jenkins_deploy_to_heroku:
	heroku git:remote --app fluidkeys-api
	git push heroku HEAD:master
