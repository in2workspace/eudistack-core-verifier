package es.in2.vcverifier.verifier.infrastructure.adapter.trustvalidation;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.Flow;

final class BoundedBodySubscriber implements HttpResponse.BodySubscriber<byte[]> {

    private final int maxBytes;
    private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    private final CompletableFuture<byte[]> body = new CompletableFuture<>();
    private Flow.Subscription subscription;

    BoundedBodySubscriber(int maxBytes) {
        this.maxBytes = maxBytes;
    }

    @Override
    public void onSubscribe(Flow.Subscription subscription) {
        this.subscription = subscription;
        subscription.request(Long.MAX_VALUE);
    }

    @Override
    public void onNext(List<ByteBuffer> items) {
        if (body.isDone()) {
            return;
        }
        for (ByteBuffer item : items) {
            if (buffer.size() + item.remaining() > maxBytes) {
                subscription.cancel();
                body.completeExceptionally(new IOException("Response body is larger than " + maxBytes + " bytes"));
                return;
            }
            byte[] bytes = new byte[item.remaining()];
            item.get(bytes);
            buffer.writeBytes(bytes);
        }
    }

    @Override
    public void onError(Throwable throwable) {
        body.completeExceptionally(throwable);
    }

    @Override
    public void onComplete() {
        body.complete(buffer.toByteArray());
    }

    @Override
    public CompletionStage<byte[]> getBody() {
        return body;
    }
}
