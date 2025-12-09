export default {
	async fetch(request, env) {
		const url = new URL(request.url);
		const { pathname } = url;

		// Health check
		if (request.method === "GET" && pathname === "/health") {
			return new Response(JSON.stringify({ ok: true }), {
				status: 200,
				headers: { "Content-Type": "application/json" },
			});
		}

		// Shopify webhooks from Store A
		if (request.method === "POST" && pathname === "/webhooks/shopify") {
			return handleShopifyWebhook(request, env);
		}

		// Manual admin sync endpoint
		if (request.method === "POST" && pathname === "/admin/sync-product") {
			return handleAdminSync(request, env);
		}

		return new Response("Not found", { status: 404 });
	},
};

async function handleShopifyWebhook(request, env) {
	// TODO: verify HMAC and shop domain
	// TODO: parse topic + product id
	// TODO: call syncProduct(productId, env)

	// Stub so you can wire webhooks without errors for now
	return new Response("ok", { status: 200 });
}

async function handleAdminSync(request, env) {
	const auth = request.headers.get("X-Admin-Token");
	if (!auth || auth !== env.ADMIN_SYNC_TOKEN) {
		return new Response("unauthorized", { status: 401 });
	}

	let body;
	try {
		body = await request.json();
	} catch {
		return new Response("invalid json", { status: 400 });
	}

	const productId = body && body.product_id;
	const forceRebuild = !!(body && body.force_rebuild);

	if (!productId) {
		return new Response("product_id required", { status: 400 });
	}

	// TODO: call syncProduct(productId, env, { forceRebuild })

	return new Response(
		JSON.stringify({ ok: true, productId, forceRebuild }),
		{ status: 200, headers: { "Content-Type": "application/json" } }
	);
}