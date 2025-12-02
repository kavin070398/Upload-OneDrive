package learn.isPossible.upload.onedrive.service;

import com.microsoft.graph.models.DriveItem;
import com.microsoft.graph.models.DriveItemCreateLinkParameterSet;
import com.microsoft.graph.models.Permission;
import com.microsoft.graph.requests.GraphServiceClient;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;

@Service
public class OneDriveUploadService {

    private final GraphServiceClient<?> graphClient;

    public OneDriveUploadService(GraphServiceClient<?> graphClient) {
        this.graphClient = graphClient;
    }

    public String uploadAndShare(MultipartFile file, String folderPath) throws IOException {

        byte[] bytes = file.getBytes();

        // 1️⃣ Upload file to OneDrive
        DriveItem uploadedItem = graphClient
                .users("kavin@gomobi.io")
                .drive()
                .root()
                .itemWithPath(folderPath + "/" + file.getOriginalFilename())
                .content()
                .buildRequest()
                .put(bytes);

        // 2️⃣ Prepare sharing link parameters
        DriveItemCreateLinkParameterSet linkParams = DriveItemCreateLinkParameterSet
                .newBuilder()
                .withType("view")         // view / edit
                .withScope("anonymous")   // anonymous / organization
                .build();

        // 3️⃣ Create sharing link
        Permission shareLink = graphClient
                .users("kavin@gomobi.io")
                .drive()
                .items(uploadedItem.id)
                .createLink(linkParams)
                .buildRequest()
                .post();

        return shareLink.link.webUrl;
    }

//    public String uploadAndShare(MultipartFile file, String folderPath) throws IOException {
//
//        byte[] bytes = file.getBytes();
//
//        // 1️⃣ Upload file
//        DriveItem uploadedItem = graphClient
//                .users("kavin@gomobi.io")
//                .drive()
//                .root()
//                .itemWithPath(folderPath + "/" + file.getOriginalFilename())
//                .content()
//                .buildRequest()
//                .put(bytes);
//
//        // 2️⃣ Generate a public (anonymous) sharing link
//        var sharingLink = graphClient
//                .users("kavin@gomobi.io")
//                .drive()
//                .items(uploadedItem.id)
//                .createLink("view", "anonymous")   // "anonymous" = no login required
//                .buildRequest()
//                .post();
//
//        return sharingLink.link.webUrl;
//    }

    public String uploadSmallFile(MultipartFile file, String folderPath) throws IOException {

        byte[] bytes = file.getBytes();

//        DriveItem uploadedItem = graphClient
//                .me()
//                .drive()
//                .root()
//                .itemWithPath(folderPath + "/" + file.getOriginalFilename())
//                .content()
//                .buildRequest()
//                .put(bytes);
        DriveItem uploadedItem = graphClient
                .users("kavin@gomobi.io")  // <<< IMPORTANT FIX
                .drive()
                .root()
                .itemWithPath(folderPath + "/" + file.getOriginalFilename())
                .content()
                .buildRequest()
                .put(bytes);

        return uploadedItem.webUrl;
    }
}
