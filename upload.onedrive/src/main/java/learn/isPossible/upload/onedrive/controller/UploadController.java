package learn.isPossible.upload.onedrive.controller;

import learn.isPossible.upload.onedrive.service.OneDriveUploadService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("/onedrive")
public class UploadController {

    private final OneDriveUploadService service;

    public UploadController(OneDriveUploadService service) {
        this.service = service;
    }

    @PostMapping("/upload")
    public ResponseEntity<String> upload(@RequestParam MultipartFile file, @RequestParam String folderPath) throws Exception {

        String url = service.uploadAndShare(file, folderPath);

        return ResponseEntity.ok("Uploaded Successfully: " + url);
    }

    @PostMapping("/upload/large")
    public ResponseEntity<String> uploadLarge(
            @RequestParam MultipartFile file,
            @RequestParam String folderPath) throws Exception {

        String url = service.uploadLargeFile(file, folderPath);

        return ResponseEntity.ok("Large File Uploaded Successfully: " + url);
    }
}

