mod algorithms;
mod app;
mod center_generated;
mod corner_generated;
mod cube;
mod details;
mod edge_generated;
mod font;
mod framerate;
mod future;
mod gl;
mod graph;
mod history;
mod mode;
mod settings;
mod style;
mod theme;
mod timer;
mod widgets;

#[cfg(not(target_arch = "wasm32"))]
mod bluetooth;

use app::App;
use gl::{CubeDrawCommand, GlContext, Vertex};

pub fn is_mobile() -> Option<bool> {
    Some(false)
}

/// Long-lived GPU resources used by the cube paint callback.  Stored in
/// egui-wgpu's `CallbackResources` so they live for the lifetime of the
/// app.
struct CubeRenderResources {
    pipeline: wgpu::RenderPipeline,
    bind_group_layout: wgpu::BindGroupLayout,
    /// Per-frame resources (re-created each frame in `prepare`).
    frame_resources: Vec<FrameDrawResources>,
}

struct FrameDrawResources {
    vertex_buffer: wgpu::Buffer,
    index_buffer: wgpu::Buffer,
    #[allow(dead_code)]
    uniform_buffer: wgpu::Buffer,
    bind_group: wgpu::BindGroup,
    index_count: u32,
    viewport: [f32; 4],
}

struct EframeApp {
    app: Box<dyn App>,
}

impl eframe::App for EframeApp {
    fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
        // Let the inner application draw its egui UI.
        self.app.update(ctx, frame);

        // Collect deferred cube draw commands from the inner app.
        let screen = ctx.screen_rect();
        let ppp = ctx.pixels_per_point();
        let width = (screen.width() * ppp) as u32;
        let height = (screen.height() * ppp) as u32;

        if frame.wgpu_render_state().is_some() && width > 0 && height > 0 {
            let mut commands: Vec<CubeDrawCommand> = Vec::new();
            {
                let mut gl = GlContext {
                    draw_commands: &mut commands,
                };
                self.app.update_gl(ctx, &mut gl);
            }

            if !commands.is_empty() {
                let callback = egui_wgpu::Callback::new_paint_callback(
                    screen,
                    CubeCallback { commands },
                );
                ctx.layer_painter(egui::LayerId::new(
                    egui::Order::Foreground,
                    egui::Id::new("cube_3d"),
                ))
                .add(callback);
            }
        }
    }

    fn clear_color(&self, _visuals: &egui::Visuals) -> [f32; 4] {
        let c = self.app.clear_color();
        [c.r(), c.g(), c.b(), c.a()]
    }
}

/// Paint callback that drives the 3D cube rendering inside the egui
/// render pass.
struct CubeCallback {
    commands: Vec<CubeDrawCommand>,
}

impl egui_wgpu::CallbackTrait for CubeCallback {
    fn prepare(
        &self,
        device: &wgpu::Device,
        _queue: &wgpu::Queue,
        _screen_descriptor: &egui_wgpu::ScreenDescriptor,
        _encoder: &mut wgpu::CommandEncoder,
        callback_resources: &mut egui_wgpu::CallbackResources,
    ) -> Vec<wgpu::CommandBuffer> {
        use wgpu::util::DeviceExt;

        let resources: &mut CubeRenderResources = callback_resources.get_mut().unwrap();
        resources.frame_resources.clear();

        for cmd in &self.commands {
            let vertex_buffer = device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
                label: Some("cube_vertex_buffer"),
                contents: bytemuck::cast_slice(&cmd.vertices),
                usage: wgpu::BufferUsages::VERTEX,
            });
            let index_buffer = device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
                label: Some("cube_index_buffer"),
                contents: bytemuck::cast_slice(&cmd.indices),
                usage: wgpu::BufferUsages::INDEX,
            });
            let uniform_buffer = device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
                label: Some("cube_uniform_buffer"),
                contents: bytemuck::bytes_of(&cmd.uniforms),
                usage: wgpu::BufferUsages::UNIFORM,
            });
            let bind_group = device.create_bind_group(&wgpu::BindGroupDescriptor {
                label: Some("cube_bind_group"),
                layout: &resources.bind_group_layout,
                entries: &[wgpu::BindGroupEntry {
                    binding: 0,
                    resource: uniform_buffer.as_entire_binding(),
                }],
            });
            resources.frame_resources.push(FrameDrawResources {
                vertex_buffer,
                index_buffer,
                uniform_buffer,
                bind_group,
                index_count: cmd.indices.len() as u32,
                viewport: cmd.viewport,
            });
        }

        Vec::new()
    }

    fn paint(
        &self,
        info: egui::PaintCallbackInfo,
        render_pass: &mut wgpu::RenderPass<'static>,
        callback_resources: &egui_wgpu::CallbackResources,
    ) {
        let resources: &CubeRenderResources = callback_resources.get().unwrap();
        render_pass.set_pipeline(&resources.pipeline);

        // Convert logical-point viewports to physical pixels using the
        // current DPI from PaintCallbackInfo, and clamp to render target.
        let target_w = info.screen_size_px[0] as f32;
        let target_h = info.screen_size_px[1] as f32;
        let ppp = info.pixels_per_point;

        for frame_res in &resources.frame_resources {
            let vp = &frame_res.viewport;
            // Convert from logical points to physical pixels.
            let x = (vp[0] * ppp).max(0.0);
            let y = (vp[1] * ppp).max(0.0);
            let w = (vp[2] * ppp).min(target_w - x);
            let h = (vp[3] * ppp).min(target_h - y);
            if w <= 0.0 || h <= 0.0 {
                continue;
            }

            render_pass.set_bind_group(0, &frame_res.bind_group, &[]);
            render_pass.set_vertex_buffer(0, frame_res.vertex_buffer.slice(..));
            render_pass.set_index_buffer(
                frame_res.index_buffer.slice(..),
                wgpu::IndexFormat::Uint16,
            );
            render_pass.set_viewport(x, y, w, h, 0.0, 1.0);
            render_pass.draw_indexed(0..frame_res.index_count, 0, 0..1);
        }
    }
}

fn build_cube_render_resources(
    device: &wgpu::Device,
    target_format: wgpu::TextureFormat,
    depth_format: Option<wgpu::TextureFormat>,
) -> CubeRenderResources {
    let shader_module = device.create_shader_module(wgpu::ShaderModuleDescriptor {
        label: Some("cube_shader"),
        source: wgpu::ShaderSource::Wgsl(include_str!("shaders/shader.wgsl").into()),
    });

    let bind_group_layout = device.create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
        label: Some("cube_bind_group_layout"),
        entries: &[wgpu::BindGroupLayoutEntry {
            binding: 0,
            visibility: wgpu::ShaderStages::VERTEX | wgpu::ShaderStages::FRAGMENT,
            ty: wgpu::BindingType::Buffer {
                ty: wgpu::BufferBindingType::Uniform,
                has_dynamic_offset: false,
                min_binding_size: None,
            },
            count: None,
        }],
    });

    let pipeline_layout = device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
        label: Some("cube_pipeline_layout"),
        bind_group_layouts: &[&bind_group_layout],
        push_constant_ranges: &[],
    });

    let vertex_buffer_layout = wgpu::VertexBufferLayout {
        array_stride: std::mem::size_of::<Vertex>() as wgpu::BufferAddress,
        step_mode: wgpu::VertexStepMode::Vertex,
        attributes: &[
            wgpu::VertexAttribute {
                format: wgpu::VertexFormat::Float32x3,
                offset: 0,
                shader_location: 0,
            },
            wgpu::VertexAttribute {
                format: wgpu::VertexFormat::Float32x3,
                offset: 12,
                shader_location: 1,
            },
            wgpu::VertexAttribute {
                format: wgpu::VertexFormat::Float32x3,
                offset: 24,
                shader_location: 2,
            },
            wgpu::VertexAttribute {
                format: wgpu::VertexFormat::Float32,
                offset: 36,
                shader_location: 3,
            },
        ],
    };

    let depth_stencil = depth_format.map(|format| wgpu::DepthStencilState {
        format,
        depth_write_enabled: true,
        depth_compare: wgpu::CompareFunction::Less,
        stencil: wgpu::StencilState::default(),
        bias: wgpu::DepthBiasState::default(),
    });

    let pipeline = device.create_render_pipeline(&wgpu::RenderPipelineDescriptor {
        label: Some("cube_render_pipeline"),
        layout: Some(&pipeline_layout),
        vertex: wgpu::VertexState {
            module: &shader_module,
            entry_point: Some("vs_main"),
            buffers: &[vertex_buffer_layout],
            compilation_options: Default::default(),
        },
        primitive: wgpu::PrimitiveState {
            topology: wgpu::PrimitiveTopology::TriangleList,
            strip_index_format: None,
            front_face: wgpu::FrontFace::Ccw,
            cull_mode: Some(wgpu::Face::Back),
            unclipped_depth: false,
            polygon_mode: wgpu::PolygonMode::Fill,
            conservative: false,
        },
        depth_stencil,
        multisample: wgpu::MultisampleState::default(),
        fragment: Some(wgpu::FragmentState {
            module: &shader_module,
            entry_point: Some("fs_main"),
            targets: &[Some(wgpu::ColorTargetState {
                format: target_format,
                blend: Some(wgpu::BlendState::REPLACE),
                write_mask: wgpu::ColorWrites::ALL,
            })],
            compilation_options: Default::default(),
        }),
        multiview: None,
        cache: None,
    });

    CubeRenderResources {
        pipeline,
        bind_group_layout,
        frame_resources: Vec::new(),
    }
}

#[tokio::main]
async fn main() {
    env_logger::init();

    let app: Box<dyn App> = match app::Application::new() {
        Ok(app) => Box::new(app),
        Err(error) => Box::new(app::ErrorApplication::new(error.to_string())),
    };

    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("TPS Cube"),
        renderer: eframe::Renderer::Wgpu,
        // Request a depth buffer so the egui render pass includes a depth
        // attachment.  The 3D cube callback relies on this for correct
        // depth-tested rendering.
        depth_buffer: 24,
        ..Default::default()
    };

    eframe::run_native(
        "TPS Cube",
        native_options,
        Box::new(move |cc| {
            let render_state = cc
                .wgpu_render_state
                .as_ref()
                .expect("wgpu render state required");
            let device = &render_state.device;
            let target_format = render_state.target_format;
            // eframe does not expose the depth format on `RenderState`, but
            // we know the depth buffer bits we requested, so compute it the
            // same way eframe does internally.
            let depth_format = egui_wgpu::depth_format_from_bits(24, 0);

            let resources = build_cube_render_resources(device, target_format, depth_format);

            render_state
                .renderer
                .write()
                .callback_resources
                .insert(resources);

            Ok(Box::new(EframeApp { app }))
        }),
    )
    .unwrap();
}
