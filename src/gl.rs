use anyhow::Result;
use egui::Rect;
use gl_matrix::{
    common::{to_radian, Mat3, Mat4, Vec3},
    mat3, mat4,
};

#[cfg(target_arch = "wasm32")]
use anyhow::anyhow;
#[cfg(target_arch = "wasm32")]
use js_sys::WebAssembly;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::JsCast;
#[cfg(target_arch = "wasm32")]
use web_sys::{HtmlCanvasElement, WebGlBuffer, WebGlProgram, WebGlRenderingContext, WebGlShader};

#[cfg(target_arch = "wasm32")]
pub struct GlContext<'a, 'b> {
    pub canvas: &'a HtmlCanvasElement,
    pub ctxt: &'b WebGlRenderingContext,
}

#[cfg(not(target_arch = "wasm32"))]
pub struct GlContext<'a> {
    pub draw_commands: &'a mut Vec<CubeDrawCommand>,
    pub screen_size: [u32; 2],
    pub pixels_per_point: f32,
}

#[cfg(not(target_arch = "wasm32"))]
pub struct CubeDrawCommand {
    pub vertices: Vec<Vertex>,
    pub indices: Vec<u16>,
    pub uniforms: CubeUniforms,
    pub viewport: [f32; 4], // x, y, width, height (pixel coords)
}

// WGSL uniform layout for Uniforms:
//   mat4x4f  view_proj_matrix  offset 0    (64 bytes)
//   mat4x4f  model_matrix      offset 64   (64 bytes)
//   mat3x3f  normal_matrix     offset 128  (48 bytes: 3 columns of vec4f with padding)
//   vec3f    camera_pos        offset 176  (12 bytes + 4 pad)
//   vec3f    light_pos         offset 192  (12 bytes + 4 pad)
//   vec3f    light_color       offset 208  (12 bytes + 4 pad)
// Total: 224 bytes
#[cfg(not(target_arch = "wasm32"))]
#[repr(C)]
#[derive(Clone, Copy, bytemuck::Pod, bytemuck::Zeroable)]
pub struct CubeUniforms {
    view_proj_matrix: [[f32; 4]; 4],
    model_matrix: [[f32; 4]; 4],
    // mat3x3f in WGSL is stored as 3 columns of vec4f (with padding)
    normal_matrix_col0: [f32; 4], // col 0 + padding
    normal_matrix_col1: [f32; 4], // col 1 + padding
    normal_matrix_col2: [f32; 4], // col 2 + padding
    camera_pos: [f32; 3],
    _pad0: f32,
    light_pos: [f32; 3],
    _pad1: f32,
    light_color: [f32; 3],
    _pad2: f32,
}

#[repr(C)]
#[derive(Clone, Copy, bytemuck::Pod, bytemuck::Zeroable)]
pub struct Vertex {
    pub pos: [f32; 3],
    pub normal: [f32; 3],
    pub color: [f32; 3],
    pub roughness: f32,
}

pub struct GlRenderer {
    #[cfg(target_arch = "wasm32")]
    program: WebGlProgram,
    #[cfg(target_arch = "wasm32")]
    index_buffer: WebGlBuffer,
    #[cfg(target_arch = "wasm32")]
    pos_buffer: WebGlBuffer,
    #[cfg(target_arch = "wasm32")]
    normal_buffer: WebGlBuffer,
    #[cfg(target_arch = "wasm32")]
    color_buffer: WebGlBuffer,
    #[cfg(target_arch = "wasm32")]
    roughness_buffer: WebGlBuffer,

    #[cfg(not(target_arch = "wasm32"))]
    viewport: [f32; 4], // x, y, width, height in pixels
    #[cfg(not(target_arch = "wasm32"))]
    view_proj: Mat4,

    camera_pos: Vec3,
    light_pos: Vec3,
    light_color: Vec3,

    view: Mat4,
    model: Mat4,
}

impl GlRenderer {
    #[cfg(target_arch = "wasm32")]
    pub fn new(gl: &GlContext<'_, '_>) -> Result<Self> {
        let shader = ShaderPrograms::default();
        let vertex_shader = compile_shader(
            gl.ctxt,
            WebGlRenderingContext::VERTEX_SHADER,
            shader.vertex_100_es,
        )
        .map_err(|error| anyhow!(error))?;

        let fragment_shader = compile_shader(
            gl.ctxt,
            WebGlRenderingContext::FRAGMENT_SHADER,
            shader.fragment_100_es,
        )
        .map_err(|error| anyhow!(error))?;

        let program = link_program(gl.ctxt, &[vertex_shader, fragment_shader])
            .map_err(|error| anyhow!(error))?;

        let index_buffer = gl
            .ctxt
            .create_buffer()
            .ok_or(anyhow!("Failed to create index buffer"))?;
        let pos_buffer = gl
            .ctxt
            .create_buffer()
            .ok_or(anyhow!("Failed to create position buffer"))?;
        let normal_buffer = gl
            .ctxt
            .create_buffer()
            .ok_or(anyhow!("Failed to create normal buffer"))?;
        let color_buffer = gl
            .ctxt
            .create_buffer()
            .ok_or(anyhow!("Failed to create color buffer"))?;
        let roughness_buffer = gl
            .ctxt
            .create_buffer()
            .ok_or(anyhow!("Failed to create roughness buffer"))?;

        let mut view: Mat4 = [0.0; 16];
        let mut model: Mat4 = [0.0; 16];
        mat4::identity(&mut view);
        mat4::identity(&mut model);
        Ok(Self {
            program,
            index_buffer,
            pos_buffer,
            normal_buffer,
            color_buffer,
            roughness_buffer,
            view,
            model,
            camera_pos: [0.0, 0.0, 0.0],
            light_pos: [0.0, 0.0, 0.0],
            light_color: [0.0, 0.0, 0.0],
        })
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub fn new(_gl: &GlContext<'_>) -> Result<Self> {
        let mut view: Mat4 = [0.0; 16];
        let mut model: Mat4 = [0.0; 16];
        mat4::identity(&mut view);
        mat4::identity(&mut model);

        Ok(Self {
            view,
            model,
            camera_pos: [0.0, 0.0, 0.0],
            light_pos: [0.0, 0.0, 0.0],
            light_color: [0.0, 0.0, 0.0],
            view_proj: [0.0; 16],
            viewport: [0.0; 4],
        })
    }

    pub fn set_light(&mut self, pos: Vec3, color: Vec3) {
        self.light_pos = pos;
        self.light_color = color;
    }

    pub fn set_camera_pos(&mut self, pos: Vec3) {
        self.camera_pos = pos;

        let mut view = [0.0; 16];
        mat4::from_translation(&mut view, &[-pos[0], -pos[1], -pos[2]]);
        self.view = view;
    }

    pub fn set_model_matrix(&mut self, model: Mat4) {
        self.model = model;
    }

    fn projection_matrix(rect: &Rect) -> Mat4 {
        let mut result: Mat4 = [0.0; 16];
        mat4::perspective(
            &mut result,
            to_radian(45.0),
            rect.width() / rect.height(),
            1.0,
            Some(100.0),
        );
        result
    }

    fn normal_matrix(&self) -> Mat3 {
        let mut result: Mat3 = [0.0; 9];
        let dest = &mut result;
        mat3::from_mat4(dest, &self.model);
        mat3::invert(dest, &mat3::clone(dest));
        mat3::transpose(dest, &mat3::clone(dest));
        result
    }

    #[cfg(target_arch = "wasm32")]
    pub fn begin(&mut self, ctxt: &egui::Context, gl: &mut GlContext<'_, '_>, rect: &Rect) {
        gl.ctxt.disable(WebGlRenderingContext::SCISSOR_TEST);
        gl.ctxt.enable(WebGlRenderingContext::CULL_FACE);
        gl.ctxt.enable(WebGlRenderingContext::DEPTH_TEST);
        gl.ctxt.depth_func(WebGlRenderingContext::LESS);
        gl.ctxt.use_program(Some(&self.program));

        gl.ctxt.viewport(
            (rect.left() * ctxt.pixels_per_point()) as i32,
            gl.canvas.height() as i32 - (rect.bottom() * ctxt.pixels_per_point()) as i32,
            (rect.width() * ctxt.pixels_per_point()) as i32,
            (rect.height() * ctxt.pixels_per_point()) as i32,
        );

        let view_proj_loc = gl
            .ctxt
            .get_uniform_location(&self.program, "view_proj_matrix")
            .unwrap();
        let proj = Self::projection_matrix(rect);
        let mut view_proj = [0.0; 16];
        mat4::multiply(&mut view_proj, &proj, &self.view);
        gl.ctxt
            .uniform_matrix4fv_with_f32_array(Some(&view_proj_loc), false, &view_proj);

        let camera_pos_loc = gl
            .ctxt
            .get_uniform_location(&self.program, "camera_pos")
            .unwrap();
        gl.ctxt
            .uniform3fv_with_f32_array(Some(&camera_pos_loc), &self.camera_pos);

        let light_pos_loc = gl
            .ctxt
            .get_uniform_location(&self.program, "light_pos")
            .unwrap();
        gl.ctxt
            .uniform3fv_with_f32_array(Some(&light_pos_loc), &self.light_pos);

        let light_color_loc = gl
            .ctxt
            .get_uniform_location(&self.program, "light_color")
            .unwrap();
        gl.ctxt
            .uniform3fv_with_f32_array(Some(&light_color_loc), &self.light_color);

        gl.ctxt.clear_depth(1.0);
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub fn begin(&mut self, _ctxt: &egui::Context, gl: &mut GlContext<'_>, rect: &Rect) {
        let ppp = gl.pixels_per_point;
        let _ = gl.screen_size; // not needed in wgpu (top-left origin)

        let x = rect.left() * ppp;
        let y = rect.top() * ppp;
        let w = rect.width() * ppp;
        let h = rect.height() * ppp;
        self.viewport = [x, y, w, h];

        let proj = Self::projection_matrix(rect);
        mat4::multiply(&mut self.view_proj, &proj, &self.view);
    }

    #[cfg(target_arch = "wasm32")]
    pub fn draw(
        &mut self,
        gl: &mut GlContext<'_, '_>,
        verts: &[Vertex],
        idx: &[u16],
    ) -> Result<()> {
        let model_loc = gl
            .ctxt
            .get_uniform_location(&self.program, "model_matrix")
            .unwrap();
        gl.ctxt
            .uniform_matrix4fv_with_f32_array(Some(&model_loc), false, &self.model);

        let normal_mat = self.normal_matrix();
        let normal_mat_loc = gl
            .ctxt
            .get_uniform_location(&self.program, "normal_matrix")
            .unwrap();
        gl.ctxt
            .uniform_matrix3fv_with_f32_array(Some(&normal_mat_loc), false, &normal_mat);

        let mut positions: Vec<f32> = Vec::new();
        let mut normals: Vec<f32> = Vec::new();
        let mut colors: Vec<f32> = Vec::new();
        let mut roughness: Vec<f32> = Vec::new();
        for vert in verts {
            positions.push(vert.pos[0]);
            positions.push(vert.pos[1]);
            positions.push(vert.pos[2]);
            normals.push(vert.normal[0]);
            normals.push(vert.normal[1]);
            normals.push(vert.normal[2]);
            colors.push(vert.color[0]);
            colors.push(vert.color[1]);
            colors.push(vert.color[2]);
            roughness.push(vert.roughness);
        }

        let memory = wasm_bindgen::memory()
            .dyn_into::<WebAssembly::Memory>()
            .map_err(|_| anyhow!("Failed to access wasm memory"))?
            .buffer();
        let index_ptr = idx.as_ptr() as u32 / 2;
        let index_array =
            js_sys::Int16Array::new(&memory).subarray(index_ptr, index_ptr + idx.len() as u32);
        gl.ctxt.bind_buffer(
            WebGlRenderingContext::ELEMENT_ARRAY_BUFFER,
            Some(&self.index_buffer),
        );
        gl.ctxt.buffer_data_with_array_buffer_view(
            WebGlRenderingContext::ELEMENT_ARRAY_BUFFER,
            &index_array,
            WebGlRenderingContext::STREAM_DRAW,
        );

        let pos_ptr = positions.as_ptr() as u32 / 4;
        let pos_array =
            js_sys::Float32Array::new(&memory).subarray(pos_ptr, pos_ptr + positions.len() as u32);

        gl.ctxt
            .bind_buffer(WebGlRenderingContext::ARRAY_BUFFER, Some(&self.pos_buffer));
        gl.ctxt.buffer_data_with_array_buffer_view(
            WebGlRenderingContext::ARRAY_BUFFER,
            &pos_array,
            WebGlRenderingContext::STREAM_DRAW,
        );

        let pos_loc = gl.ctxt.get_attrib_location(&self.program, "pos");
        assert!(pos_loc >= 0);
        let pos_loc = pos_loc as u32;

        gl.ctxt.vertex_attrib_pointer_with_i32(
            pos_loc,
            3,
            WebGlRenderingContext::FLOAT,
            false,
            0,
            0,
        );
        gl.ctxt.enable_vertex_attrib_array(pos_loc);

        let normal_ptr = normals.as_ptr() as u32 / 4;
        let normal_array = js_sys::Float32Array::new(&memory)
            .subarray(normal_ptr, normal_ptr + normals.len() as u32);

        gl.ctxt.bind_buffer(
            WebGlRenderingContext::ARRAY_BUFFER,
            Some(&self.normal_buffer),
        );
        gl.ctxt.buffer_data_with_array_buffer_view(
            WebGlRenderingContext::ARRAY_BUFFER,
            &normal_array,
            WebGlRenderingContext::STREAM_DRAW,
        );

        let normal_loc = gl.ctxt.get_attrib_location(&self.program, "normal");
        assert!(normal_loc >= 0);
        let normal_loc = normal_loc as u32;

        gl.ctxt.vertex_attrib_pointer_with_i32(
            normal_loc,
            3,
            WebGlRenderingContext::FLOAT,
            false,
            0,
            0,
        );
        gl.ctxt.enable_vertex_attrib_array(normal_loc);

        let colors_ptr = colors.as_ptr() as u32 / 4;
        let colors_array = js_sys::Float32Array::new(&memory)
            .subarray(colors_ptr, colors_ptr + colors.len() as u32);

        gl.ctxt.bind_buffer(
            WebGlRenderingContext::ARRAY_BUFFER,
            Some(&self.color_buffer),
        );
        gl.ctxt.buffer_data_with_array_buffer_view(
            WebGlRenderingContext::ARRAY_BUFFER,
            &colors_array,
            WebGlRenderingContext::STREAM_DRAW,
        );

        let color_loc = gl.ctxt.get_attrib_location(&self.program, "color");
        assert!(color_loc >= 0);
        let color_loc = color_loc as u32;

        gl.ctxt.vertex_attrib_pointer_with_i32(
            color_loc,
            3,
            WebGlRenderingContext::FLOAT,
            false,
            0,
            0,
        );
        gl.ctxt.enable_vertex_attrib_array(color_loc);

        let roughness_ptr = roughness.as_ptr() as u32 / 4;
        let roughness_array = js_sys::Float32Array::new(&memory)
            .subarray(roughness_ptr, roughness_ptr + roughness.len() as u32);

        gl.ctxt.bind_buffer(
            WebGlRenderingContext::ARRAY_BUFFER,
            Some(&self.roughness_buffer),
        );
        gl.ctxt.buffer_data_with_array_buffer_view(
            WebGlRenderingContext::ARRAY_BUFFER,
            &roughness_array,
            WebGlRenderingContext::STREAM_DRAW,
        );

        let roughness_loc = gl.ctxt.get_attrib_location(&self.program, "roughness");
        assert!(roughness_loc >= 0);
        let roughness_loc = roughness_loc as u32;

        gl.ctxt.vertex_attrib_pointer_with_i32(
            roughness_loc,
            1,
            WebGlRenderingContext::FLOAT,
            false,
            0,
            0,
        );
        gl.ctxt.enable_vertex_attrib_array(roughness_loc);

        gl.ctxt.draw_elements_with_i32(
            WebGlRenderingContext::TRIANGLES,
            idx.len() as i32,
            WebGlRenderingContext::UNSIGNED_SHORT,
            0,
        );

        Ok(())
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub fn draw(
        &mut self,
        gl: &mut GlContext<'_>,
        verts: &[Vertex],
        idx: &[u16],
    ) -> Result<()> {
        let normal_mat = self.normal_matrix();

        let view_proj = [
            [self.view_proj[0], self.view_proj[1], self.view_proj[2], self.view_proj[3]],
            [self.view_proj[4], self.view_proj[5], self.view_proj[6], self.view_proj[7]],
            [self.view_proj[8], self.view_proj[9], self.view_proj[10], self.view_proj[11]],
            [self.view_proj[12], self.view_proj[13], self.view_proj[14], self.view_proj[15]],
        ];
        let model = [
            [self.model[0], self.model[1], self.model[2], self.model[3]],
            [self.model[4], self.model[5], self.model[6], self.model[7]],
            [self.model[8], self.model[9], self.model[10], self.model[11]],
            [self.model[12], self.model[13], self.model[14], self.model[15]],
        ];

        let uniforms = CubeUniforms {
            view_proj_matrix: view_proj,
            model_matrix: model,
            // mat3x3f columns with vec4f padding
            normal_matrix_col0: [normal_mat[0], normal_mat[1], normal_mat[2], 0.0],
            normal_matrix_col1: [normal_mat[3], normal_mat[4], normal_mat[5], 0.0],
            normal_matrix_col2: [normal_mat[6], normal_mat[7], normal_mat[8], 0.0],
            camera_pos: self.camera_pos,
            _pad0: 0.0,
            light_pos: self.light_pos,
            _pad1: 0.0,
            light_color: self.light_color,
            _pad2: 0.0,
        };

        gl.draw_commands.push(CubeDrawCommand {
            vertices: verts.to_vec(),
            indices: idx.to_vec(),
            uniforms,
            viewport: self.viewport,
        });

        Ok(())
    }

    #[cfg(target_arch = "wasm32")]
    pub fn end(&mut self, gl: &mut GlContext<'_, '_>) {
        gl.ctxt
            .viewport(0, 0, gl.canvas.width() as i32, gl.canvas.height() as i32);
        gl.ctxt.disable(WebGlRenderingContext::DEPTH_TEST);
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub fn end(&mut self, _gl: &mut GlContext<'_>) {}
}

#[cfg(target_arch = "wasm32")]
struct ShaderPrograms {
    vertex_100_es: &'static str,
    fragment_100_es: &'static str,
}

#[cfg(target_arch = "wasm32")]
impl ShaderPrograms {
    fn default() -> Self {
        ShaderPrograms {
            vertex_100_es: include_str!("shaders/vertex_100es.glsl"),
            fragment_100_es: include_str!("shaders/fragment_100es.glsl"),
        }
    }
}

#[cfg(target_arch = "wasm32")]
pub(crate) fn compile_shader(
    gl: &WebGlRenderingContext,
    shader_type: u32,
    source: &str,
) -> Result<WebGlShader, String> {
    let shader = gl
        .create_shader(shader_type)
        .ok_or_else(|| String::from("Unable to create shader object"))?;
    gl.shader_source(&shader, source);
    gl.compile_shader(&shader);

    if gl
        .get_shader_parameter(&shader, WebGlRenderingContext::COMPILE_STATUS)
        .as_bool()
        .unwrap_or(false)
    {
        Ok(shader)
    } else {
        Err(gl
            .get_shader_info_log(&shader)
            .unwrap_or_else(|| "Unknown error creating shader".into()))
    }
}

#[cfg(target_arch = "wasm32")]
pub(crate) fn link_program<'a, T: IntoIterator<Item = &'a WebGlShader>>(
    gl: &WebGlRenderingContext,
    shaders: T,
) -> Result<WebGlProgram, String> {
    let program = gl
        .create_program()
        .ok_or_else(|| String::from("Unable to create shader object"))?;
    for shader in shaders {
        gl.attach_shader(&program, shader)
    }
    gl.link_program(&program);

    if gl
        .get_program_parameter(&program, WebGlRenderingContext::LINK_STATUS)
        .as_bool()
        .unwrap_or(false)
    {
        Ok(program)
    } else {
        Err(gl
            .get_program_info_log(&program)
            .unwrap_or_else(|| "Unknown error creating program object".into()))
    }
}
