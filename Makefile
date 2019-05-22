test:
	mvn -s settings.xml test \
		-DreleaseTesting -Danalyzer.node.package.enabled=false \
		-Danalyzer.node.audit.enabled=false \
		-Dtest=CsvAnalyzerTest -pl core

.PHONY: test
