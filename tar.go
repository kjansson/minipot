package main

import "archive/tar"

func writeTar(tarWriter *tar.Writer, name string, data []byte) error {
	tarHeader := &tar.Header{
		Name: name,
		Size: int64(len(data)),
	}
	err := tarWriter.WriteHeader(tarHeader)
	if err != nil {
		return err
	}
	_, err = tarWriter.Write(data)
	if err != nil {
		return err
	}
	return nil
}
