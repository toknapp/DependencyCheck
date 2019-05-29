test:
	mvn -s settings.xml test \
		-DreleaseTesting -Danalyzer.node.package.enabled=false \
		-Danalyzer.node.audit.enabled=false \
		-Dtest=CsvAnalyzerTest -pl core

package:
	mvn -s settings.xml package

run: package
	./zip-runner.sh cli/target/dependency-check-5.0.0-M3-release.zip \
		--scan=./core/src/test/resources/csv \
		--log=log --data=/tmp/DependencyCheck/h2

clean:
	rm -rf core/target cli/target target

.PHONY: test cli run
