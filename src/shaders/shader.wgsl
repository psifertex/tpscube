// PBR shader ported from GLSL to WGSL

struct Uniforms {
    view_proj_matrix: mat4x4f,
    model_matrix: mat4x4f,
    normal_matrix: mat3x3f,
    camera_pos: vec3f,
    light_pos: vec3f,
    light_color: vec3f,
}

@group(0) @binding(0) var<uniform> uniforms: Uniforms;

struct VertexInput {
    @location(0) pos: vec3f,
    @location(1) normal: vec3f,
    @location(2) color: vec3f,
    @location(3) roughness: f32,
}

struct VertexOutput {
    @builtin(position) clip_pos: vec4f,
    @location(0) world_pos: vec3f,
    @location(1) normal: vec3f,
    @location(2) color: vec3f,
    @location(3) roughness: f32,
}

@vertex
fn vs_main(in: VertexInput) -> VertexOutput {
    var out: VertexOutput;
    out.world_pos = (uniforms.model_matrix * vec4f(in.pos, 1.0)).xyz;
    out.normal = uniforms.normal_matrix * in.normal;
    out.clip_pos = uniforms.view_proj_matrix * vec4f(out.world_pos, 1.0);
    out.color = in.color;
    out.roughness = in.roughness;
    return out;
}

// PBR functions

const PI: f32 = 3.14159265358979;

fn DistributionGGX(N: vec3f, H: vec3f, roughness: f32) -> f32 {
    let a = roughness * roughness;
    let a_squared = a * a;
    let NdotH = max(dot(N, H), 0.0);
    let denom = NdotH * NdotH * (a_squared - 1.0) + 1.0;
    return a_squared / (PI * denom * denom);
}

fn GeometrySchlickGGX(NdotV: f32, roughness: f32) -> f32 {
    let r = roughness + 1.0;
    let k = (r * r) / 8.0;
    return NdotV / (NdotV * (1.0 - k) + k);
}

fn GeometrySmith(N: vec3f, V: vec3f, L: vec3f, roughness: f32) -> f32 {
    return GeometrySchlickGGX(max(dot(N, L), 0.0), roughness) *
           GeometrySchlickGGX(max(dot(N, V), 0.0), roughness);
}

fn FresnelSchlick(cosTheta: f32, F0: vec3f) -> vec3f {
    return F0 + (1.0 - F0) * pow(1.0 - cosTheta, 5.0);
}

@fragment
fn fs_main(in: VertexOutput) -> @location(0) vec4f {
    let N = normalize(in.normal);
    let V = normalize(uniforms.camera_pos - in.world_pos);
    let ao = 1.0;

    var Lo = vec3f(0.0);

    // Single point light
    let L = normalize(uniforms.light_pos - in.world_pos);
    let H = normalize(V + L);
    let dist = length(uniforms.light_pos - in.world_pos);
    let radiance = uniforms.light_color * (1.0 / (dist * dist));

    let NDF = DistributionGGX(N, H, in.roughness);
    let G = GeometrySmith(N, V, L, in.roughness);
    let F = FresnelSchlick(max(dot(H, V), 0.0), vec3f(0.04));

    let kD = vec3f(1.0) - F;
    let spec = (NDF * G * F) / (4.0 * max(dot(N, V), 0.0) * max(dot(N, L), 0.0) + 0.001);
    Lo += (kD * in.color / PI + spec) * radiance * max(dot(N, L), 0.0);

    let ambient = vec3f(0.05) * in.color * ao;
    let linear_color = ambient + Lo;

    // Convert linear to sRGB for display (egui-wgpu surface is non-sRGB
    // format but expects sRGB-encoded values for proper display).
    let cutoff = linear_color < vec3f(0.0031308);
    let lower = linear_color * 12.92;
    let higher = 1.055 * pow(linear_color, vec3f(1.0 / 2.4)) - 0.055;
    let srgb = select(higher, lower, cutoff);

    return vec4f(srgb, 1.0);
}
