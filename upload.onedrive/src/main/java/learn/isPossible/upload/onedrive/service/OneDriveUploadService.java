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
                .users("mobitest@gomobi.io")
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
                .users("mobitest@gomobi.io")
                .drive()
                .items(uploadedItem.id)
                .createLink(linkParams)
                .buildRequest()
                .post();

        return shareLink.link.webUrl;
    }

    public String uploadLargeFile(MultipartFile file, String folderPath) throws Exception {

        // 1. Create upload session
        var uploadSession = graphClient
                .users("kavin@gomobi.io")
                .drive()
                .root()
                .itemWithPath(folderPath + "/" + file.getOriginalFilename())
                .createUploadSession(null)
                .buildRequest()
                .post();

        String uploadUrl = uploadSession.uploadUrl;
        int chunkSize = 5 * 1024 * 1024; // 5MB
        byte[] fileBytes = file.getBytes();

        int totalSize = fileBytes.length;
        int offset = 0;

        okhttp3.OkHttpClient client = new okhttp3.OkHttpClient();

        // 2. Upload chunks
        while (offset < totalSize) {

            int end = Math.min(offset + chunkSize, totalSize);
            byte[] chunk = new byte[end - offset];
            System.arraycopy(fileBytes, offset, chunk, 0, chunk.length);

            okhttp3.Request request = new okhttp3.Request.Builder()
                    .url(uploadUrl)
                    .addHeader("Content-Length", String.valueOf(chunk.length))
                    .addHeader("Content-Range",
                            "bytes " + offset + "-" + (end - 1) + "/" + totalSize)
                    .put(okhttp3.RequestBody.create(chunk))
                    .build();

            okhttp3.Response response = client.newCall(request).execute();

            // Final chunk returns DriveItem
            if (response.code() == 201 || response.code() == 200) {
                String body = response.body().string();

                // Parse final metadata returned by OneDrive
                DriveItem uploadedItem =
                        graphClient.getSerializer().deserializeObject(body, DriveItem.class);

                // 3. Create share link
                var linkParams = DriveItemCreateLinkParameterSet
                        .newBuilder()
                        .withType("view")
                        .withScope("anonymous")
                        .build();

                Permission shareLink = graphClient
                        .users("kavin@gomobi.io")
                        .drive()
                        .items(uploadedItem.id)
                        .createLink(linkParams)
                        .buildRequest()
                        .post();

                return shareLink.link.webUrl;
            }

            response.close();
            offset = end;
        }

        throw new RuntimeException("Upload failed — no final response returned");
    }
}
