pipeline {
    agent any

    triggers {
        githubPush() // auto-trigger on push
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Build') {
            steps {
                echo "Building project..."
                sh 'mvn clean install -DskipTests' // if it's Maven project
            }
        }

        stage('Test') {
            steps {
                echo "Running tests..."
                sh 'mvn test' // run unit tests
            }
        }

        stage('Commit Info') {
            steps {
                echo "Branch: ${env.GIT_BRANCH}"
                echo "Commit: ${env.GIT_COMMIT}"
                sh 'git log -1 --pretty=format:"%h - %an: %s"'
            }
        }
    }

    post {
        success {
            echo "✅ Build succeeded for commit ${env.GIT_COMMIT}"
        }
        failure {
            echo "❌ Build failed for commit ${env.GIT_COMMIT}"
        }
    }
}
