pipeline {
    agent any

    // triggers {
    //     githubPush() // auto-trigger on push
    // }

    stages {
        stage('Check Java Version') {
            steps {
                sh 'java -version'
            }
        }


        // stage('Build') {
        //     steps {
        //         echo "Building project..."
        //         sh 'mvn clean install -DskipTests' // For Maven projects
        //     }
        // }

        stage ("test") {
            steps {
                sh '''
                    mvn --version
                '''
            }
        }
        

        // stage('Test') {
        //     steps {
        //         echo "Running tests..."
        //         sh 'mvn test'
        //     }
        // }

    //     stage('Commit Info') {
    //         steps {
    //             echo "Branch: ${env.GIT_BRANCH}"
    //             echo "Commit: ${env.GIT_COMMIT}"

    //             script {
    //                 // Get the author of the last commit
    //                 def author = sh(
    //                     script: "git log -1 --pretty=format:'%an <%ae>'",
    //                     returnStdout: true
    //                 ).trim()
    //                 echo "Commit Author: ${author}"

    //                 // Optional: get committer (who actually pushed)
    //                 def committer = sh(
    //                     script: "git log -1 --pretty=format:'%cn <%ce>'",
    //                     returnStdout: true
    //                 ).trim()
    //                 echo "Committer: ${committer}"
    //             }
    //         }
    //     }
    // }

    // post {
    //     success {
    //         echo "✅ Build succeeded for commit ${env.GIT_COMMIT}"
    //     }
    //     failure {
    //         echo "❌ Build failed for commit ${env.GIT_COMMIT}"
    //     }
    }
}
