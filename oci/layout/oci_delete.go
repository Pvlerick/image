package layout

import (
	"bytes"
	"context"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/containers/image/v5/internal/set"
	"github.com/containers/image/v5/types"
	digest "github.com/opencontainers/go-digest"
	imgspecv1 "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/sirupsen/logrus"
)

// DeleteImage deletes the named image from the directory, if supported.
func (ref ociReference) DeleteImage(ctx context.Context, sys *types.SystemContext) error {
	// Scan all the manifests in the directory:
	// ... collect the one that matches with the received ref
	// ... and store all the blobs used in all other images
	var imageDescriptorWrapper *descriptorWrapper
	blobsUsedByOtherImages := set.New[digest.Digest]()
	allDescriptors, err := ref.getAllImageDescriptorsInDirectory()
	if err != nil {
		return err
	}

	if ref.image == "" {
		if len(allDescriptors) == 1 {
			imageDescriptorWrapper = &allDescriptors[0]
		} else {
			return ErrMoreThanOneImage
		}
	} else {
		for _, v := range allDescriptors {
			if v.descriptor.Annotations[imgspecv1.AnnotationRefName] == ref.image {
				tmpDescriptionWrapper := v
				imageDescriptorWrapper = &tmpDescriptionWrapper
			} else {
				otherImageManifest, err := ref.getManifest(v.descriptor)
				if err != nil {
					return err
				}
				blobsUsedByOtherImages.Add(otherImageManifest.Config.Digest)
				for _, layer := range otherImageManifest.Layers {
					blobsUsedByOtherImages.Add(layer.Digest)
				}
			}
		}
	}

	if ref.image != "" && imageDescriptorWrapper == nil {
		return ImageNotFoundError{ref}
	}

	manifest, err := ref.getManifest(imageDescriptorWrapper.descriptor)
	if err != nil {
		return err
	}

	// Delete all blobs used by this image only
	blobsToDelete := set.New[digest.Digest]()
	for _, descriptor := range append(manifest.Layers, manifest.Config, *imageDescriptorWrapper.descriptor) {
		if !blobsUsedByOtherImages.Contains(descriptor.Digest) {
			blobsToDelete.Add(descriptor.Digest)
		} else {
			logrus.Debug("Blob ", descriptor.Digest.Hex(), " is used by another image, leaving it")
		}
	}
	for _, digest := range blobsToDelete.Values() {
		//TODO Check if there is shared blob path?
		blobPath, err := ref.blobPath(digest, "")
		if err != nil {
			return err
		}
		logrus.Debug("Deleting blob ", digest.Hex())
		err = os.Remove(blobPath)
		if err != nil && !os.IsNotExist(err) {
			return err
		}
	}

	// This holds the step to be done on the current index, as we walk back bottom up
	step := indexUpdateStep{"delete", imageDescriptorWrapper.descriptor.Digest, nil}

	for i := len(imageDescriptorWrapper.indexChain) - 1; i >= 0; i-- {
		indexPath := imageDescriptorWrapper.indexChain[i]
		index, err := parseIndex(indexPath)
		if err != nil {
			return err
		}
		// Fill new index with existing manifests except the one we are removing
		newManifests := make([]imgspecv1.Descriptor, 0, len(index.Manifests))
		for _, v := range index.Manifests {
			if v.Digest == step.digest {
				switch step.action {
				case "delete":
					continue
				case "update":
					newDescriptor := v
					newDescriptor.Digest = *step.newDigest
					newManifests = append(newManifests, newDescriptor)
				}
			} else {
				newManifests = append(newManifests, v)
			}
		}
		index.Manifests = newManifests

		// New index is ready, it has to be saved to disk now
		// ... if it is the root index, it's easy, just overwrite it
		if indexPath == ref.indexPath() {
			return saveJSON(ref.indexPath(), index)
		} else {
			indexDigest, err := digest.Parse("sha256:" + filepath.Base(indexPath))
			if err != nil {
				return err
			}
			// In a nested index, if the new index is empty it has to be remove,
			// otherwise update the parent index with the new hash
			if len(index.Manifests) == 0 {
				step = indexUpdateStep{"delete", indexDigest, nil}
			} else {
				// Save the new file
				buffer := new(bytes.Buffer)
				err = json.NewEncoder(buffer).Encode(index)
				if err != nil {
					return err
				}
				indexNewDigest := digest.Canonical.FromBytes(buffer.Bytes())
				indexNewPath, err := ref.blobPath(indexNewDigest, "")
				if err != nil {
					return err
				}
				err = saveJSON(indexNewPath, index)
				if err != nil {
					return err
				}
				step = indexUpdateStep{"update", indexDigest, &indexNewDigest}
			}
			// Delete the current index if it is not reference anywhere else;
			// it is dangling by now as it'll either be empty or have a new hash
			if !blobsUsedByOtherImages.Contains(indexDigest) {
				err = os.Remove(indexPath)
				if err != nil {
					return err
				}
			}
		}
	}

	return nil
}

func saveJSON(path string, content any) error {
	// If the file already exists, get its mode to preserve it
	var mode fs.FileMode
	existingfi, err := os.Stat(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		} else { // File does not exist, use default mode
			mode = 0644
		}
	} else {
		mode = existingfi.Mode()
	}

	// Then write the file
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer file.Close()

	return json.NewEncoder(file).Encode(content)
}

// Stores an (image) descriptor along with the index it was found in and its parents if any
// this allows the update of the index when an image is located in a nested (++) index
type descriptorWrapper struct {
	descriptor *imgspecv1.Descriptor
	indexChain []string //in order of appearence, the first is always be index.json and the nested indexes, last one being the one where the descriptor was found in
}

// This will return all the descriptors of all the images found in the directory
// It starts at the index.json and then walks all nested indexes
// Each image descriptor is returned along with the index it was found, as well as it parents if it is a nested index
func (ref ociReference) getAllImageDescriptorsInDirectory() ([]descriptorWrapper, error) {
	descriptors := make([]descriptorWrapper, 0)
	var getImageDescriptorsFromIndex func(indexChain []string) error
	getImageDescriptorsFromIndex = func(indexChain []string) error {
		index, err := parseIndex(indexChain[len(indexChain)-1]) // last item in the index is always the index in which whe are currently working
		if err != nil {
			return err
		}

		for _, manifestDescriptor := range index.Manifests {
			switch manifestDescriptor.MediaType {
			case imgspecv1.MediaTypeImageManifest:
				tmpManifestDescriptor := manifestDescriptor
				wrapper := descriptorWrapper{&tmpManifestDescriptor, indexChain}
				descriptors = append(descriptors, wrapper)
			case imgspecv1.MediaTypeImageIndex:
				nestedIndexBlobPath, err := ref.blobPath(manifestDescriptor.Digest, "")
				if err != nil {
					return err
				}
				// recursively get manifests from this nested index
				err = getImageDescriptorsFromIndex(append(indexChain, nestedIndexBlobPath))
				if err != nil {
					return err
				}
			}
		}
		return nil
	}

	err := getImageDescriptorsFromIndex([]string{ref.indexPath()}) //Start the walk at the root (index.json)
	return descriptors, err
}

func (ref ociReference) getManifest(descriptor *imgspecv1.Descriptor) (*imgspecv1.Manifest, error) {
	//TODO Check if there is shared blob path?
	manifestPath, err := ref.blobPath(descriptor.Digest, "")
	if err != nil {
		return nil, err
	}

	manifest, err := parseJSON[imgspecv1.Manifest](manifestPath)
	if err != nil {
		return nil, err
	}

	return manifest, nil
}

type indexUpdateStep struct {
	action    string
	digest    digest.Digest
	newDigest *digest.Digest
}
