import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    kotlin("jvm") version "1.5.20"
    id("com.github.hierynomus.license") version "0.16.1"
    application
}

group = "com.github.jonathanxd"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencies {
    // GPG
    implementation("org.bouncycastle:bcpg-jdk15on:1.69")
    testImplementation(kotlin("test"))
}

tasks.test {
    useJUnitPlatform()
}

tasks.withType<KotlinCompile>() {
    kotlinOptions.jvmTarget = "1.8"
}

tasks.withType<nl.javadude.gradle.plugins.license.License> {
    header = rootProject.file("LICENSE")
    strictCheck = true
}