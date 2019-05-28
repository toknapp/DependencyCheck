test:
	mvn -s settings.xml test \
		-DreleaseTesting -Danalyzer.node.package.enabled=false \
		-Danalyzer.node.audit.enabled=false \
		-Dtest=CsvAnalyzerTest -pl core

cli:
	mvn -s settings.xml -pl cli package

run: cli
	./zip-runner.sh cli/target/dependency-check-5.0.0-M3-release.zip

.PHONY: test cli run
