// Build, "make check", publish. Nothing else.
//
// This exists to prove the Jenkins side works before Jenkinsfile.security
// runs anything expensive: that the job reaches the bare repository, that the
// workspace holds a tree the Makefile recognises, that archiveArtifacts fills
// in Last Successful Artifacts, and that the build description renders.
//
// "make check" is the whole test stage. Makefile.am's check-local extends it
// with check-spaces, check-changes, check-includes and shellcheck, so this is
// the same test surface .github/workflows/ci.yml has.
//
// The binary this publishes comes off a development branch, not off upstream
// tor. That branch carries changes that are not upstream, and they go
// upstream one at a time as each is ready; some are there to be measured
// rather than kept. Whoever downloads the artifact is running a fork, so the
// publish stage writes that into BUILDINFO beside the binary rather than
// leaving it to be inferred from the version string.
//
// The name is Jenkinsfile so Script Path can stay at its default.

pipeline {
  agent any

  options {
    disableConcurrentBuilds()
    timestamps()
    buildDiscarder(logRotator(numToKeepStr: '30', artifactNumToKeepStr: '10'))
  }

  parameters {
    string(name: 'JOBS', defaultValue: '2',
           description: 'make -j value. Each cc1 on the larger tor files takes a few hundred MB.')
  }

  stages {

    stage('Build') {
      steps {
        sh '''
          set -e
          # artifacts/ is not a Makefile directory, so distclean leaves it and
          # it survives into the next build. The archive pattern ends in "*",
          # so without this build 5 would publish the binaries from builds 1
          # through 5.
          rm -rf artifacts
          ./autogen.sh
          ./configure --enable-fatal-warnings --disable-asciidoc
          make -j"${JOBS}"
        '''
      }
    }

    stage('Test') {
      steps {
        sh 'make check'
      }
      post {
        // test-suite.log names which test failed and why. It is written into
        // the workspace, which the cleanup block distcleans, so it has to be
        // taken now or not at all.
        failure {
          archiveArtifacts artifacts: 'test-suite.log, src/test/*.log, config.log',
                           allowEmptyArchive: true
        }
      }
    }

    stage('Publish') {
      when {
        expression {
          sh(script: 'test "$(uname -s)" = Linux && test "$(uname -m)" = x86_64',
             returnStatus: true) == 0
        }
      }
      steps {
        sh '''
          set -e
          mkdir -p artifacts
          rev=$(cat micro-revision.i)
          # A binary that cannot name its commit is not much use for reporting
          # a bug against, and the string is invisible unless someone reads it.
          if [ "$rev" = '""' ]; then
            echo "no git revision embedded"; exit 1
          fi

          bin="artifacts/tor-linux-amd64-${BUILD_NUMBER}"
          cp src/app/tor "$bin"

          # Split rather than discard, in this order: the stripped binary keeps
          # its GNU build-id, which is the value gdb and perf pair it with its
          # symbols by. Same three commands the GitHub workflow uses, so an
          # artifact from either side symbolicates the same way.
          objcopy --only-keep-debug "$bin" "$bin.debug"
          strip "$bin"
          objcopy --add-gnu-debuglink="$bin.debug" "$bin"

          id_bin=$(readelf -n "$bin" | awk '/Build ID/{print $3}')
          id_dbg=$(readelf -n "$bin.debug" | awk '/Build ID/{print $3}')
          if [ -z "$id_bin" ] || [ "$id_bin" != "$id_dbg" ]; then
            echo "build ids do not match, the debuginfo is unusable"
            echo "binary $id_bin / debuginfo $id_dbg"
            exit 1
          fi
          readelf -S "$bin.debug" | grep -q '\\.debug_info' || {
            echo "$bin.debug carries no DWARF"; exit 1; }
          file "$bin" | grep -q 'not stripped' && {
            echo "$bin was not stripped"; exit 1; }

          "$bin" --version

          # Every field is read out of the tree or off the binary, so none of
          # it can disagree with the binary it describes. The version comes
          # from the expression the GitHub workflow uses for the release tag.
          ver=$(sed -n 's/^AC_INIT(\\[tor\\],\\[\\(.*\\)\\])$/\\1/p' configure.ac)
          {
            echo "tor $ver"
            echo "commit         $(echo "$rev" | tr -d '\\"')"
            echo "build          #${BUILD_NUMBER}"
            echo "built          $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
            echo "platform       linux-amd64"
            echo "gnu build-id   $id_bin"
            echo
            echo "files"
            for f in "$bin" "$bin.debug"; do
              printf '  %-40s %s\\n' "$(basename "$f")" "$(du -h "$f" | cut -f1)"
            done
            echo
            echo "tested with    make check"
            echo
            echo "about this build"
            echo "  A development branch of tor, not upstream tor. It carries"
            echo "  changes that are not upstream; each one goes upstream when"
            echo "  it is ready, and some are here to be measured rather than"
            echo "  kept. Unsigned, and not a release."
          } > "artifacts/BUILDINFO-${BUILD_NUMBER}.txt"
          cat "artifacts/BUILDINFO-${BUILD_NUMBER}.txt"

          # Handed to the Groovy side, which cannot read the shell's variables.
          {
            echo "TOR_VERSION=$ver"
            echo "TOR_BUILD_ID=$id_bin"
            echo "TOR_COMMIT=$(echo "$rev" | tr -d '\\"')"
          } > .buildinfo.properties
        '''
        script {
          // The build description is the one part of the page a pipeline can
          // write without script approval. readFile rather than
          // readProperties: the latter needs the Pipeline Utility Steps
          // plugin, and this needs three strings.
          //
          // A for loop over readLines() rather than eachLine with a closure.
          // eachLine is a GDK method, so Java code drives the closure, and
          // the pipeline's CPS transformation cuts the body off at its first
          // transformed call. The first line lands in the map and the rest do
          // not, which showed up as "@ null" and "build-id null" in the
          // description of build 6 while BUILDINFO.txt held the right values.
          def info = [:]
          for (String line : readFile('.buildinfo.properties').readLines()) {
            int eq = line.indexOf('=')
            if (eq > 0) { info[line.substring(0, eq)] = line.substring(eq + 1) }
          }
          currentBuild.description =
            "tor ${info.TOR_VERSION} @ ${info.TOR_COMMIT}\n" +
            "linux-amd64, build-id ${info.TOR_BUILD_ID}"
        }
      }
      post {
        success {
          // fingerprint ties each file back to the build that made it, which
          // is what lets someone holding a downloaded binary find its log.
          archiveArtifacts artifacts: 'artifacts/tor-linux-amd64-*, artifacts/BUILDINFO-*.txt',
                           fingerprint: true
        }
      }
    }
  }

  post {
    cleanup {
      // The build tree is around 300 MB and nothing else removes it, so it
      // would sit in the workspace between builds.
      //
      // A bare sh here fails with "Required context class hudson.FilePath is
      // missing" when the pipeline ends without ever having had a workspace,
      // which a pipeline-level post block can do: it runs even when the
      // failure came before the agent was allocated. getContext returns null
      // in exactly that case, so ask before running a step that needs one.
      script {
        if (getContext(hudson.FilePath)) {
          sh 'make -s distclean || true'
        }
      }
    }
  }
}
