// src/index.js

export default {
	async fetch(request, env) {
		const url = new URL(request.url);
		const { pathname } = url;

		console.log("REQUEST", {
			method: request.method,
			pathname,
		});

		// Health check
		if (request.method === "GET" && pathname === "/health") {
			return new Response(JSON.stringify({ ok: true }), {
				status: 200,
				headers: { "Content-Type": "application/json" },
			});
		}

		// Shopify webhooks from source store (Store A)
		if (request.method === "POST" && pathname === "/webhooks/shopify") {
			return handleShopifyWebhook(request, env);
		}

		// Manual admin-triggered sync of a single product
		if (request.method === "POST" && pathname === "/admin/sync-product") {
			return handleAdminSync(request, env);
		}

		// One-off backfill: attach existing Rhino products by SKU
		if (
			request.method === "POST" &&
			pathname === "/admin/backfill-rhino-mappings"
		) {
			return handleBackfillRhinoMappings(request, env);
		}

		return new Response("Not found", { status: 404 });
	},
};

async function handleShopifyWebhook(request, env) {
	const shopDomain = request.headers.get("X-Shopify-Shop-Domain");
	const topic = request.headers.get("X-Shopify-Topic") || "";
	const hmacHeader = request.headers.get("X-Shopify-Hmac-Sha256") || "";

	// Only accept webhooks from the source store
	if (!shopDomain || shopDomain !== env.SHOPIFY_SOURCE_DOMAIN) {
		return new Response("ignored", { status: 200 });
	}

	// Read raw body once
	const bodyArrayBuffer = await request.arrayBuffer();
	const bodyBytes = new Uint8Array(bodyArrayBuffer);

	// Verify HMAC
	const hmacOk = await verifyShopifyHmac(
		bodyBytes,
		hmacHeader,
		env.SHOPIFY_SOURCE_WEBHOOK_SECRET
	);

	if (!hmacOk) {
		return new Response("invalid hmac", { status: 401 });
	}

	// Parse JSON payload
	let payload;
	try {
		const text = new TextDecoder().decode(bodyBytes);
		payload = JSON.parse(text);
	} catch {
		return new Response("invalid json", { status: 400 });
	}

	// Determine which product to sync
	const productId = extractProductIdFromWebhook(topic, payload);

	if (!productId) {
		// Not a product we care about
		return new Response("ignored", { status: 200 });
	}

	try {
		await syncProduct(productId, env);
	} catch (err) {
		console.error("syncProduct failed", err);
		// 500 so Shopify can retry
		return new Response("sync error", { status: 500 });
	}

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
	const forceRebuild = !!(body && (body.forceRebuild || body.force_rebuild));

	if (!productId) {
		return new Response("product_id required", { status: 400 });
	}

	try {
		await syncProduct(productId, env, { forceRebuild });
	} catch (err) {
		console.error("admin syncProduct failed", err);
		return new Response("sync error", { status: 500 });
	}

	return new Response(
		JSON.stringify({ ok: true, productId, forceRebuild }),
		{ status: 200, headers: { "Content-Type": "application/json" } }
	);
}

/**
 * One-off backfill for Rhino mappings, by SKU.
 * Only products whose autospec_sync.targets includes rhino/autospec_rhino.
 */
async function handleBackfillRhinoMappings(request, env) {
	const auth = request.headers.get("X-Admin-Token");
	if (!auth || auth !== env.ADMIN_SYNC_TOKEN) {
		return new Response("unauthorized", { status: 401 });
	}

	try {
		console.log("backfill-rhino: start");

		// Sanity check Rhino config
		if (!env.SHOPIFY_RHINO_DOMAIN || !env.SHOPIFY_RHINO_ADMIN_TOKEN) {
			return new Response(
				JSON.stringify({
					ok: false,
					error: "Missing SHOPIFY_RHINO_DOMAIN or SHOPIFY_RHINO_ADMIN_TOKEN",
				}),
				{ status: 500, headers: { "Content-Type": "application/json" } }
			);
		}

		// 1) Fetch all products from source and Rhino
		const [sourceProducts, rhinoProducts] = await Promise.all([
			fetchAllSourceProducts(env),
			fetchAllRhinoProducts(env),
		]);

		console.log("backfill-rhino: fetched products", {
			sourceCount: sourceProducts.length,
			rhinoCount: rhinoProducts.length,
		});

		// 2) Build SKU index for Rhino
		const rhinoSkuIndex = buildRhinoSkuIndex(rhinoProducts);

		// 3) Walk through all source products and map ones with rhino target
		let scanned = 0;
		let candidates = 0;
		let mapped = 0;
		let skippedNoSku = 0;
		let skippedNoMatch = 0;
		let skippedAmbiguous = 0;
		let errors = 0;

		for (const p of sourceProducts) {
			scanned++;

			try {
				const {
					targets,
					remoteIds,
					remoteIdsMetafieldId,
					remoteIdsRawValue,
				} = await fetchSourceSyncMetafields(p.id, env);

				// Only products explicitly targeted at Rhino
				if (!targets.includes("autospec_rhino")) {
					continue;
				}

				candidates++;

				const skus = (p.variants || [])
					.map((v) => v.sku)
					.filter((s) => !!s);

				if (skus.length === 0) {
					skippedNoSku++;
					console.log("backfill-rhino: skip product with no SKUs", {
						sourceProductId: p.id,
					});
					continue;
				}

				// Try to match all SKUs to Rhino
				const variantMap = {};
				const productIdsSet = new Set();

				let allFound = true;
				for (const sku of skus) {
					const entry = rhinoSkuIndex[sku];
					if (!entry) {
						allFound = false;
						break;
					}
					variantMap[sku] = entry.variantId;
					productIdsSet.add(entry.productId);
				}

				if (!allFound) {
					skippedNoMatch++;
					console.log("backfill-rhino: no complete SKU match", {
						sourceProductId: p.id,
						skus,
					});
					continue;
				}

				if (productIdsSet.size !== 1) {
					skippedAmbiguous++;
					console.log("backfill-rhino: ambiguous SKU match", {
						sourceProductId: p.id,
						skus,
					});
					continue;
				}

				const rhinoProductId = [...productIdsSet][0];

				// Build updated remoteIds object; overwrite autospec_rhino
				const newRemoteIds =
					remoteIds && typeof remoteIds === "object" ? { ...remoteIds } : {};
				newRemoteIds.autospec_rhino = {
					product_id: rhinoProductId,
					variants_by_sku: variantMap,
				};

				// Write metafield back to Store A
				await upsertRemoteIdsMetafield(
					p.id,
					newRemoteIds,
					remoteIdsMetafieldId,
					remoteIdsRawValue,
					env
				);

				mapped++;
				console.log("backfill-rhino: mapped product", {
					sourceProductId: p.id,
					rhinoProductId,
					skuCount: skus.length,
				});
			} catch (err) {
				errors++;
				console.error("backfill-rhino: error for product", {
					sourceProductId: p.id,
					error: String(err),
				});
			}
		}

		const summary = {
			ok: true,
			scanned,
			candidates,
			mapped,
			skippedNoSku,
			skippedNoMatch,
			skippedAmbiguous,
			errors,
		};

		console.log("backfill-rhino: done", summary);

		return new Response(JSON.stringify(summary), {
			status: 200,
			headers: { "Content-Type": "application/json" },
		});
	} catch (err) {
		console.error("backfill-rhino: fatal error", err);
		return new Response(
			JSON.stringify({ ok: false, error: String(err) }),
			{ status: 500, headers: { "Content-Type": "application/json" } }
		);
	}
}

/**
 * Verify Shopify webhook HMAC using the store-level webhook secret.
 */
async function verifyShopifyHmac(bodyBytes, hmacHeader, secret) {
	if (!hmacHeader || !secret) return false;

	const enc = new TextEncoder();
	const keyData = enc.encode(secret);

	const cryptoKey = await crypto.subtle.importKey(
		"raw",
		keyData,
		{ name: "HMAC", hash: "SHA-256" },
		false,
		["sign"]
	);

	const signature = await crypto.subtle.sign("HMAC", cryptoKey, bodyBytes);
	const expectedHmac = arrayBufferToBase64(signature);

	return safeCompare(expectedHmac, hmacHeader);
}

function arrayBufferToBase64(buffer) {
	let binary = "";
	const bytes = new Uint8Array(buffer);
	const len = bytes.byteLength;
	for (let i = 0; i < len; i++) {
		binary += String.fromCharCode(bytes[i]);
	}
	return btoa(binary);
}

function safeCompare(a, b) {
	if (!a || !b || a.length !== b.length) return false;
	let result = 0;
	for (let i = 0; i < a.length; i++) {
		result |= a.charCodeAt(i) ^ b.charCodeAt(i);
	}
	return result === 0;
}

/**
 * Extract product id from webhook payload depending on topic.
 */
function extractProductIdFromWebhook(topic, payload) {
	if (topic.startsWith("products/")) {
		return payload && payload.id;
	}
	return null;
}

/**
 * Core sync:
 *  - fetch product + autospec_sync metafields from Store A
 *  - compute targets (defaulting to autospec_perth)
 *  - create/update products in Perth and Rhino based on targets
 *  - write back autospec_sync.remote_ids on Store A (only when changed)
 */
async function syncProduct(productId, env, options = {}) {
	const forceRebuild = !!options.forceRebuild;

	const sourceProduct = await fetchSourceProduct(productId, env);

	const {
		targets,
		remoteIds,
		remoteIdsMetafieldId,
		remoteIdsRawValue,
	} = await fetchSourceSyncMetafields(productId, env);

	let effectiveTargets = targets && targets.length ? targets.slice() : [];
	if (effectiveTargets.length === 0) {
		effectiveTargets = ["autospec_perth"];
	}

	console.log("syncProduct start", {
		productId,
		effectiveTargets,
		hasPerthDomain: !!env.SHOPIFY_PERTH_DOMAIN,
		hasPerthToken: !!env.SHOPIFY_PERTH_ADMIN_TOKEN,
		hasRhinoDomain: !!env.SHOPIFY_RHINO_DOMAIN,
		hasRhinoToken: !!env.SHOPIFY_RHINO_ADMIN_TOKEN,
	});

	const updatedRemoteIds =
		remoteIds && typeof remoteIds === "object" ? { ...remoteIds } : {};

	const allStoreCodes = ["autospec_perth", "autospec_rhino"];

	for (const storeCode of allStoreCodes) {
		const shouldTarget = effectiveTargets.includes(storeCode);
		const existing = updatedRemoteIds[storeCode];

		if (!shouldTarget) continue;

		const cfg = getStoreConfigOrNull(storeCode, env);
		if (!cfg) {
			console.error("Missing config for store, skipping", {
				storeCode,
			});
			continue;
		}

		const entry = await syncToStoreWithConfig(
			sourceProduct,
			storeCode,
			existing,
			cfg,
			env,
			forceRebuild
		);
		updatedRemoteIds[storeCode] = entry;
	}

	await upsertRemoteIdsMetafield(
		productId,
		updatedRemoteIds,
		remoteIdsMetafieldId,
		remoteIdsRawValue,
		env
	);

	console.log("syncProduct done", {
		productId,
		forceRebuild,
		effectiveTargets,
		updatedRemoteIds,
	});
}

/**
 * Sync one target store with an already-resolved config.
 */
async function syncToStoreWithConfig(
	sourceProduct,
	storeCode,
	existingMapping,
	cfg,
	env,
	forceRebuild
) {
	if (!existingMapping || !existingMapping.product_id || forceRebuild) {
		const entry = await createProductInStoreWithConfig(
			sourceProduct,
			storeCode,
			cfg,
			env
		);
		console.log("Created product in store", {
			storeCode,
			sourceProductId: sourceProduct.id,
			targetProductId: entry.product_id,
		});
		return entry;
	}

	const entry = await updateProductInStoreWithConfig(
		sourceProduct,
		existingMapping,
		storeCode,
		cfg,
		env
	);
	console.log("Updated product in store", {
		storeCode,
		sourceProductId: sourceProduct.id,
		targetProductId: entry.product_id,
	});
	return entry;
}

/**
 * Fetch product from source store (Store A)
 */
async function fetchSourceProduct(productId, env) {
	const path = `/admin/api/${env.SHOPIFY_API_VERSION}/products/${productId}.json`;

	const res = await shopifyRequest(
		env.SHOPIFY_SOURCE_DOMAIN,
		env.SHOPIFY_SOURCE_ADMIN_TOKEN,
		"GET",
		path
	);

	if (!res.ok) {
		throw new Error(
			`Failed to fetch product ${productId} from source: ${res.status}`
		);
	}

	const data = await res.json();
	return data.product;
}

/**
 * Fetch all products from Store A (source) via REST pagination.
 */
async function fetchAllSourceProducts(env) {
	return fetchAllProductsForShop(
		env.SHOPIFY_SOURCE_DOMAIN,
		env.SHOPIFY_SOURCE_ADMIN_TOKEN,
		env.SHOPIFY_API_VERSION
	);
}

/**
 * Fetch all products from Rhino via REST pagination.
 */
async function fetchAllRhinoProducts(env) {
	return fetchAllProductsForShop(
		env.SHOPIFY_RHINO_DOMAIN,
		env.SHOPIFY_RHINO_ADMIN_TOKEN,
		env.SHOPIFY_API_VERSION
	);
}

/**
 * Generic "fetch all products" via page_info pagination.
 */
async function fetchAllProductsForShop(domain, token, apiVersion) {
	const all = [];
	let pageInfo = null;

	// Hard cap to avoid infinite loops if Shopify does something weird
	const maxPages = 50;
	let pageCount = 0;

	while (true) {
		pageCount++;
		if (pageCount > maxPages) break;

		let path = `/admin/api/${apiVersion}/products.json?limit=250`;
		if (pageInfo) {
			path += `&page_info=${encodeURIComponent(pageInfo)}`;
		}

		const res = await shopifyRequest(domain, token, "GET", path);
		if (!res.ok) {
			const text = await res.text();
			throw new Error(
				`Failed to fetch products from ${domain}: ${res.status} ${text}`
			);
		}

		const data = await res.json();
		const products = data.products || [];
		all.push(...products);

		const link = res.headers.get("link") || res.headers.get("Link");
		if (!link || !link.includes('rel="next"')) {
			break;
		}

		const match = link.match(/<[^>]*[?&]page_info=([^&>]*)[^>]*>; rel="next"/);
		if (!match) {
			break;
		}
		pageInfo = match[1];
	}

	return all;
}

/**
 * Build SKU index for Rhino products: sku -> { productId, variantId }
 */
function buildRhinoSkuIndex(rhinoProducts) {
	const index = {};
	for (const p of rhinoProducts) {
		for (const v of p.variants || []) {
			const sku = v.sku;
			if (!sku) continue;
			index[sku] = {
				productId: p.id,
				variantId: v.id,
			};
		}
	}
	return index;
}

/**
 * Normalise a target string to canonical storeCode.
 */
function normalizeTargetCode(code) {
	if (!code) return null;
	const c = String(code).toLowerCase().trim();
	if (c === "perth" || c === "autospec_perth") return "autospec_perth";
	if (c === "rhino" || c === "autospec_rhino") return "autospec_rhino";
	return null;
}

/**
 * Fetch autospec_sync.targets and autospec_sync.remote_ids metafields from Store A.
 */
async function fetchSourceSyncMetafields(productId, env) {
	const path = `/admin/api/${env.SHOPIFY_API_VERSION}/products/${productId}/metafields.json?namespace=autospec_sync`;

	const res = await shopifyRequest(
		env.SHOPIFY_SOURCE_DOMAIN,
		env.SHOPIFY_SOURCE_ADMIN_TOKEN,
		"GET",
		path
	);

	if (!res.ok) {
		throw new Error(
			`Failed to fetch metafields for product ${productId}: ${res.status}`
		);
	}

	const data = await res.json();
	const metafields = data.metafields || [];

	let targets = [];
	let remoteIds = {};
	let remoteIdsMetafieldId = null;
	let remoteIdsRawValue = null;

	for (const mf of metafields) {
		if (mf.key === "targets") {
			let rawTargets = [];
			try {
				const parsed = JSON.parse(mf.value);
				if (Array.isArray(parsed)) {
					rawTargets = parsed;
				} else if (typeof parsed === "string" && parsed.trim()) {
					rawTargets = parsed.split(",").map((s) => s.trim());
				}
			} catch {
				if (typeof mf.value === "string" && mf.value.trim()) {
					rawTargets = mf.value.split(",").map((s) => s.trim());
				}
			}
			targets = rawTargets.map(normalizeTargetCode).filter((x) => !!x);
		}

		if (mf.key === "remote_ids") {
			remoteIdsMetafieldId = mf.id;
			remoteIdsRawValue = mf.value;
			// In API 2021-01+, JSON metafields are returned as objects, not strings
			if (typeof mf.value === "object" && mf.value !== null) {
				remoteIds = mf.value;
			} else if (typeof mf.value === "string") {
				try {
					const parsed = JSON.parse(mf.value);
					if (parsed && typeof parsed === "object") {
						remoteIds = parsed;
					}
				} catch {
					console.warn("Failed to parse remote_ids JSON for", productId);
				}
			}
		}
	}

	return { targets, remoteIds, remoteIdsMetafieldId, remoteIdsRawValue };
}

/**
 * Return store config or null, do not throw.
 */
function getStoreConfigOrNull(storeCode, env) {
	if (storeCode === "autospec_perth") {
		if (!env.SHOPIFY_PERTH_DOMAIN || !env.SHOPIFY_PERTH_ADMIN_TOKEN) {
			return null;
		}
		return {
			domain: env.SHOPIFY_PERTH_DOMAIN,
			token: env.SHOPIFY_PERTH_ADMIN_TOKEN,
		};
	}
	if (storeCode === "autospec_rhino") {
		if (!env.SHOPIFY_RHINO_DOMAIN || !env.SHOPIFY_RHINO_ADMIN_TOKEN) {
			return null;
		}
		return {
			domain: env.SHOPIFY_RHINO_DOMAIN,
			token: env.SHOPIFY_RHINO_ADMIN_TOKEN,
		};
	}
	return null;
}

/**
 * Try to adopt an existing product in target store by SKU only.
 * If multiple products share that SKU, pick one deterministically (lowest product_id).
 * Returns a mapping if adoption succeeded, or null if no SKU / no match.
 */
async function tryAdoptExistingProductBySku(
	sourceProduct,
	storeCode,
	cfg,
	env
) {
	const version = env.SHOPIFY_API_VERSION;

	const firstSku =
		(sourceProduct.variants || []).map((v) => v.sku).find((s) => !!s) || null;

	if (!firstSku) {
		return null;
	}

	const path = `/admin/api/${version}/variants.json?sku=${encodeURIComponent(
		firstSku
	)}`;

	const res = await shopifyRequest(cfg.domain, cfg.token, "GET", path);
	if (!res.ok) {
		const text = await res.text();
		console.warn("tryAdoptExistingProductBySku: variants lookup failed", {
			storeCode,
			sku: firstSku,
			status: res.status,
			text,
		});
		return null;
	}

	const data = await res.json();
	const variants = data.variants || [];
	if (variants.length === 0) {
		return null;
	}

	const productIds = variants
		.map((v) => v.product_id)
		.filter((id) => id !== null && id !== undefined);

	if (productIds.length === 0) {
		return null;
	}

	// Deterministically pick the smallest product_id
	const chosenProductId = productIds.reduce((min, id) => {
		return min === null || id < min ? id : min;
	}, null);

	if (chosenProductId === null) {
		return null;
	}

	if (new Set(productIds).size > 1) {
		console.warn("tryAdoptExistingProductBySku: multiple product_ids for SKU", {
			storeCode,
			sku: firstSku,
			allProductIds: Array.from(new Set(productIds)),
			chosenProductId,
		});
	} else {
		console.log("tryAdoptExistingProductBySku: single product match by SKU", {
			storeCode,
			sku: firstSku,
			productId: chosenProductId,
		});
	}

	const mapping = { product_id: chosenProductId };
	const entry = await updateProductInStoreWithConfig(
		sourceProduct,
		mapping,
		storeCode,
		cfg,
		env
	);

	console.log("tryAdoptExistingProductBySku: adopted product", {
		storeCode,
		sourceProductId: sourceProduct.id,
		targetProductId: entry.product_id,
		sku: firstSku,
	});

	return entry;
}

/**
 * Create a new product in target store from source product.
 * First tries to adopt an existing product by SKU, then falls back to POST.
 * Uses X-Idempotency-Key to avoid duplicate creation if called twice.
 */
async function createProductInStoreWithConfig(
	sourceProduct,
	storeCode,
	cfg,
	env
) {
	// 1) Try to adopt an existing product by SKU only
	const adopted = await tryAdoptExistingProductBySku(
		sourceProduct,
		storeCode,
		cfg,
		env
	);
	if (adopted) {
		return adopted;
	}

	// 2) Fall back to creating a new product with idempotency
	const path = `/admin/api/${env.SHOPIFY_API_VERSION}/products.json`;

	const payload = {
		product: buildProductPayloadFromSource(sourceProduct),
	};

	// Idempotency key per source product + target store
	const idempotencyKey = `product-sync-${storeCode}-${sourceProduct.id}`;

	const res = await shopifyRequest(
		cfg.domain,
		cfg.token,
		"POST",
		path,
		payload,
		idempotencyKey
	);

	if (!res.ok) {
		const text = await res.text();
		throw new Error(
			`Failed to create product in ${storeCode}: ${res.status} ${text}`
		);
	}

	const data = await res.json();
	const created = data.product;

	const variantsBySku = {};
	for (const v of created.variants || []) {
		if (v.sku) {
			variantsBySku[v.sku] = v.id;
		}
	}

	return {
		product_id: created.id,
		variants_by_sku: variantsBySku,
	};
}

/**
 * Update existing product in target store from source product.
 */
async function updateProductInStoreWithConfig(
	sourceProduct,
	mapping,
	storeCode,
	cfg,
	env
) {
	const targetProductId = mapping.product_id;
	const path = `/admin/api/${env.SHOPIFY_API_VERSION}/products/${targetProductId}.json`;

	const currentRes = await shopifyRequest(cfg.domain, cfg.token, "GET", path);

	if (!currentRes.ok) {
		const text = await currentRes.text();
		throw new Error(
			`Failed to fetch existing product ${targetProductId} in ${storeCode}: ${currentRes.status} ${text}`
		);
	}

	const currentData = await currentRes.json();
	const current = currentData.product;

	const existingVariantIdsBySku = {};
	for (const v of current.variants || []) {
		if (v.sku) {
			existingVariantIdsBySku[v.sku] = v.id;
		}
	}

	const base = buildProductPayloadFromSource(sourceProduct);

	const updatedVariants = (base.variants || []).map((v) => {
		const sku = v.sku;
		if (sku && existingVariantIdsBySku[sku]) {
			return { ...v, id: existingVariantIdsBySku[sku] };
		}
		return v;
	});

	const updatePayload = {
		product: {
			id: targetProductId,
			title: base.title,
			body_html: base.body_html,
			vendor: base.vendor,
			product_type: base.product_type,
			status: base.status,
			handle: base.handle,
			tags: base.tags,
			template_suffix: base.template_suffix,
			options: base.options,
			variants: updatedVariants,
			images: base.images,
		},
	};

	const res = await shopifyRequest(
		cfg.domain,
		cfg.token,
		"PUT",
		path,
		updatePayload
	);

	if (!res.ok) {
		const text = await res.text();
		throw new Error(
			`Failed to update product ${targetProductId} in ${storeCode}: ${res.status} ${text}`
		);
	}

	const updatedData = await res.json();
	const updated = updatedData.product;

	const variantsBySku = {};
	for (const v of updated.variants || []) {
		if (v.sku) {
			variantsBySku[v.sku] = v.id;
		}
	}

	return {
		product_id: updated.id,
		variants_by_sku: variantsBySku,
	};
}

/**
 * Create or update autospec_sync.remote_ids metafield on Store A.
 * Only writes when there is something to store and the JSON value changed.
 */
async function upsertRemoteIdsMetafield(
	productId,
	remoteIdsObject,
	existingMetafieldId,
	existingRawValue,
	env
) {
	const value = JSON.stringify(remoteIdsObject || {});
	const version = env.SHOPIFY_API_VERSION;

	if (!remoteIdsObject || Object.keys(remoteIdsObject).length === 0) {
		return;
	}

	// Compare values, handling both string and object formats from Shopify
	const existingValue =
		typeof existingRawValue === "object"
			? JSON.stringify(existingRawValue)
			: existingRawValue;

	if (existingMetafieldId && existingValue && existingValue === value) {
		return;
	}

	if (existingMetafieldId) {
		const path = `/admin/api/${version}/metafields/${existingMetafieldId}.json`;
		const payload = {
			metafield: {
				id: existingMetafieldId,
				value,
			},
		};
		const res = await shopifyRequest(
			env.SHOPIFY_SOURCE_DOMAIN,
			env.SHOPIFY_SOURCE_ADMIN_TOKEN,
			"PUT",
			path,
			payload
		);
		if (!res.ok) {
			const text = await res.text();
			throw new Error(
				`Failed to update remote_ids metafield: ${res.status} ${text}`
			);
		}
	} else {
		const path = `/admin/api/${version}/products/${productId}/metafields.json`;
		const payload = {
			metafield: {
				namespace: "autospec_sync",
				key: "remote_ids",
				type: "json",
				value,
			},
		};
		const res = await shopifyRequest(
			env.SHOPIFY_SOURCE_DOMAIN,
			env.SHOPIFY_SOURCE_ADMIN_TOKEN,
			"POST",
			path,
			payload
		);
		if (!res.ok) {
			const text = await res.text();
			throw new Error(
				`Failed to create remote_ids metafield: ${res.status} ${text}`
			);
		}
	}
}

/**
 * Build product payload for target store from source product.
 */
function buildProductPayloadFromSource(sourceProduct) {
	const product = {
		title: sourceProduct.title,
		body_html: sourceProduct.body_html,
		vendor: sourceProduct.vendor,
		product_type: sourceProduct.product_type,
		status: sourceProduct.status,
		handle: sourceProduct.handle,
		tags: sourceProduct.tags,
		template_suffix: sourceProduct.template_suffix || null,
		options: (sourceProduct.options || []).map((o) => ({
			name: o.name,
			position: o.position,
		})),
		variants: (sourceProduct.variants || []).map((v) => ({
			sku: v.sku,
			title: v.title,
			option1: v.option1,
			option2: v.option2,
			option3: v.option3,
			price: v.price,
			compare_at_price: v.compare_at_price,
			weight: v.weight,
			weight_unit: v.weight_unit,
			barcode: v.barcode,
			taxable: v.taxable,
			requires_shipping: v.requires_shipping,
			inventory_management: v.inventory_management,
			inventory_policy: v.inventory_policy,
		})),
		images: (sourceProduct.images || []).map((img) => ({
			src: img.src,
			alt: img.alt,
			position: img.position,
		})),
	};

	return product;
}

/**
 * Generic Shopify REST call.
 * Optional idempotencyKey will be sent as X-Idempotency-Key.
 */
async function shopifyRequest(
	shopDomain,
	token,
	method,
	path,
	body,
	idempotencyKey
) {
	const url = `https://${shopDomain}${path}`;

	const headers = {
		"X-Shopify-Access-Token": token,
		"Content-Type": "application/json",
	};

	if (idempotencyKey) {
		headers["X-Idempotency-Key"] = idempotencyKey;
	}

	const init = { method, headers };

	if (body !== undefined) {
		init.body = typeof body === "string" ? body : JSON.stringify(body);
	}

	return fetch(url, init);
}