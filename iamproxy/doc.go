// Package iamproxy emulates Amazon RDS IAM, Google Cloud SQL IAM, and Azure
// Database Microsoft Entra authentication in front of stock MySQL and
// PostgreSQL servers.
//
// Start runs the database listeners and mock credential endpoints inside the
// calling process. Clients reach listeners over loopback TCP, or without a
// socket through Emulator.DialContext; packages pgxdial and mysqldial adapt
// common drivers to the latter.
package iamproxy
